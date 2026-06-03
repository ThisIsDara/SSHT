package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	SSHServer      string `json:"ssh_server"`
	SSHPort        int    `json:"ssh_port"`
	SSHUser        string `json:"ssh_user"`
	SSHKey         string `json:"ssh_key"`
	SSHPassword    string `json:"ssh_password"`
	SOCKSPort      int    `json:"socks_port"`
	SOCKSUser      string `json:"socks_user,omitempty"`
	SOCKSPass      string `json:"socks_pass,omitempty"`
	UDPGWPort      int    `json:"udpgw_port"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

var (
	tunnelID      int
	mu            sync.Mutex
	startTime     time.Time
	udpgwPort     int
	config        *Config
)

func main() {
	defer pauseOnFatal()
	startTime = time.Now()
	clearScreen()

	config = loadConfig()
	printBanner()
	printSummary(config)

	udpgwPort = config.UDPGWPort

	auth := buildAuth(config)
	client := connectSSH(config, auth)
	defer client.Close()

	msgOk("SSH", "connected — %s", client.ServerVersion())

	go func() {
		for {
			time.Sleep(60 * time.Second)
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				return
			}
		}
	}()

	socks := startSOCKS(config.SOCKSPort)
	defer socks.Close()

	var udpgw net.Listener
	if config.UDPGWPort > 0 {
		udpgw = startUDPGW(config.UDPGWPort, client)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println()
		msgWarn("Core", "shutting down...")
		socks.Close()
		if udpgw != nil {
			udpgw.Close()
		}
		client.Close()
		os.Exit(0)
	}()

	printReady(config)

	for {
		c, err := socks.Accept()
		if err != nil {
			break
		}
		go handleConn(c, client)
	}
}

func loadConfig() *Config {
	name := "config.json"
	if _, e := os.Stat(name); os.IsNotExist(e) {
		exe, _ := os.Executable()
		name = filepath.Join(filepath.Dir(exe), "config.json")
	}
	b, err := os.ReadFile(name)
	if err != nil {
		msgFatal("Config", "can't read %s", filepath.Base(name))
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		msgFatal("Config", "invalid JSON: %v", err)
	}
	if c.SSHPort == 0 {
		c.SSHPort = 22
	}
	if c.SOCKSPort == 0 {
		c.SOCKSPort = 1080
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 30
	}
	return &c
}

func buildAuth(c *Config) []ssh.AuthMethod {
	var m []ssh.AuthMethod
	if c.SSHPassword != "" {
		m = append(m, ssh.Password(c.SSHPassword))
		m = append(m, ssh.KeyboardInteractive(func(_, _ string, q []string, _ []bool) ([]string, error) {
			a := make([]string, len(q))
			for i := range q {
				a[i] = c.SSHPassword
			}
			return a, nil
		}))
		msgOk("Auth", "password ready")
	}
	if c.SSHKey != "" {
		s, err := loadKey(c.SSHKey)
		if err == nil {
			m = append(m, ssh.PublicKeys(s))
			msgOk("Auth", "key ready (%s)", filepath.Base(c.SSHKey))
		} else {
			msgWarn("Auth", "key not loaded: %v", err)
		}
	}
	if len(m) == 0 {
		msgFatal("Auth", "no auth method — set ssh_key or ssh_password")
	}
	return m
}

func loadKey(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

func tuneConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

func connectSSH(c *Config, m []ssh.AuthMethod) *ssh.Client {
	addr := net.JoinHostPort(c.SSHServer, fmt.Sprint(c.SSHPort))
	msgInfo("SSH", "checking %s ...", addr)
	tcp, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		msgFatal("SSH", "%v\n  └ server unreachable on port %d", err, c.SSHPort)
	}
	tcp.Close()
	msgOk("SSH", "host reachable")

	msgInfo("SSH", "authenticating as %s ...", c.SSHUser)
	cfg := &ssh.ClientConfig{
		User:            c.SSHUser,
		Auth:            m,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(c.TimeoutSeconds) * time.Second,
	}

	tcp2, err := net.DialTimeout("tcp", addr, time.Duration(c.TimeoutSeconds)*time.Second)
	if err != nil {
		msgFatal("SSH", "cannot connect: %v", err)
	}
	tuneConn(tcp2)

	cc, chans, reqs, err := ssh.NewClientConn(tcp2, addr, cfg)
	if err != nil {
		tcp2.Close()
		msgFatal("SSH", "auth failed after %ds: %v", c.TimeoutSeconds, err)
	}
	cl := ssh.NewClient(cc, chans, reqs)
	return cl
}

func startSOCKS(port int) net.Listener {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		msgFatal("SOCKS", "cannot bind %s: %v", addr, err)
	}
	msgOk("SOCKS", "listening on %s", addr)
	return l
}

func startUDPGW(port int, cl *ssh.Client) net.Listener {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		msgWarn("UDPGW", "cannot bind %s: %v", addr, err)
		return nil
	}
	msgOk("UDPGW", "forwarding %s → remote :%d", addr, port)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				break
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tuneConn(conn)
				r, e := cl.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
				if e != nil {
					msgDbg("UDPGW", "%s refused: %v", conn.RemoteAddr(), e)
					return
				}
				defer r.Close()
				tuneConn(r)
				msgDbg("UDPGW", "%s connected", conn.RemoteAddr())
				done := make(chan bool, 2)
				go pipe(r, conn, done)
				go pipe(conn, r, done)
				<-done
			}(c)
		}
	}()
	return l
}

func handleConn(conn net.Conn, cl *ssh.Client) {
	br := bufio.NewReaderSize(conn, 4096)
	peek, err := br.Peek(1)
	if err != nil {
		conn.Close()
		return
	}
	switch {
	case peek[0] == 5: // SOCKS5
		handleSOCKSRead(br, conn, cl)
	case peek[0] == 'C' || peek[0] == 'c': // HTTP CONNECT
		handleHTTPConnect(br, conn, cl)
	default:
		msgDbg("Proxy", "unknown protocol byte 0x%02x", peek[0])
		conn.Close()
	}
}

func handleSOCKS(conn net.Conn, cl *ssh.Client) {
	handleSOCKSRead(bufio.NewReaderSize(conn, 4096), conn, cl)
}

func handleSOCKSRead(r io.Reader, conn net.Conn, cl *ssh.Client) {
	mu.Lock()
	tunnelID++
	id := tunnelID
	mu.Unlock()
	defer conn.Close()
	tuneConn(conn)

	addr := conn.RemoteAddr().String()

	if err := socksHandshake(r, conn); err != nil {
		msgDbg("SOCKS", "#%d %s handshake: %v", id, addr, err)
		return
	}
	cmd, host, port, err := socksRequest(r)
	if err != nil {
		msgDbg("SOCKS", "#%d %s request: %v", id, addr, err)
		return
	}

	switch cmd {
	case 1:
		handleTCPConn(conn, cl, id, addr, host, port)
	case 3:
		handleUDPAssociate(conn, cl, id, addr)
	default:
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		msgDbg("SOCKS", "#%d %s unsupported cmd %d", id, addr, cmd)
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 || ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 || ip4[0] == 192 && ip4[1] == 168 ||
			ip4[0] == 127 || ip4[0] == 169 && ip4[1] == 254
	}
	return false
}

func dnsLookup(ctx context.Context, server string, host string) ([]net.IP, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", server+":53")
		},
	}
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func firstPublicIPv4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if !isPrivateIP(ip) && ip.To4() != nil {
			return ip
		}
	}
	return nil
}

func resolveWithFallback(host string) (string, bool) {
	if net.ParseIP(host) != nil {
		return host, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1) Try local DNS
	if ips, err := net.DefaultResolver.LookupHost(ctx, host); err == nil {
		var parsed []net.IP
		for _, a := range ips {
			if ip := net.ParseIP(a); ip != nil {
				parsed = append(parsed, ip)
			}
		}
		if ip := firstPublicIPv4(parsed); ip != nil {
			return ip.String(), false
		}
	}

	// 2) Try public DNS (8.8.8.8)
	if ips, err := dnsLookup(ctx, "8.8.8.8", host); err == nil {
		if ip := firstPublicIPv4(ips); ip != nil {
			return ip.String(), false
		}
	}

	// 3) Try Cloudflare DNS (1.1.1.1)
	if ips, err := dnsLookup(ctx, "1.1.1.1", host); err == nil {
		if ip := firstPublicIPv4(ips); ip != nil {
			return ip.String(), false
		}
	}

	// 4) Ultimate fallback: let SSH server resolve
	return host, true
}

func handleTCPConn(conn net.Conn, cl *ssh.Client, id int, addr, host, port string) {
	r, fallback := resolveWithFallback(host)
	if fallback {
		msgDbg("SOCKS", "#%d DNS → server-resolve %s", id, host)
	} else if r != host {
		msgDbg("SOCKS", "#%d DNS %s → %s", id, host, r)
		host = r
	}
	target, err := cl.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		msgDbg("SOCKS", "#%d %s → %s:%s refused: %v", id, addr, host, port, err)
		return
	}
	defer target.Close()
	tuneConn(target)
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	h := host
	if len(h) > 50 {
		h = h[:50] + "..."
	}
	fmt.Println("  " + GRAY + DIM + time.Now().Format("15:04:05") + RST + " " + AMB + "➜" + RST + " #" + fmt.Sprint(id) + "  " + GRAY + DIM + addr + RST + " → " + CYN + strings.ToLower(h) + RST + ":" + BLD + port + RST)

	done := make(chan bool, 2)
	go pipe(target, conn, done)
	go pipe(conn, target, done)
	<-done
}

func socksHandshake(r io.Reader, conn net.Conn) error {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	if b[0] != 5 {
		return fmt.Errorf("not SOCKS5")
	}
	nmethods := int(b[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}

	// Pick method: prefer 0 (no auth), then 2 (user/pass) if configured
	method := byte(0)
	for _, m := range methods {
		if m == 0 {
			break
		}
		if m == 2 && config.SOCKSUser != "" {
			method = 2
		}
	}
	if method == 2 && config.SOCKSUser == "" {
		method = 0
	}

	if _, err := conn.Write([]byte{5, method}); err != nil {
		return err
	}

	if method == 2 {
		// Read auth: version(1) + ulen(1) + uname + plen(1) + passwd
		ah := make([]byte, 2)
		if _, err := io.ReadFull(r, ah); err != nil {
			return err
		}
		uname := make([]byte, int(ah[1]))
		if _, err := io.ReadFull(r, uname); err != nil {
			return err
		}
		ph := make([]byte, 1)
		if _, err := io.ReadFull(r, ph); err != nil {
			return err
		}
		passwd := make([]byte, int(ph[0]))
		if _, err := io.ReadFull(r, passwd); err != nil {
			return err
		}

		if string(uname) != config.SOCKSUser || string(passwd) != config.SOCKSPass {
			conn.Write([]byte{1, 1}) // auth failed
			return fmt.Errorf("SOCKS5 auth failed")
		}
		conn.Write([]byte{1, 0}) // auth success
	}

	return nil
}

func socksRequest(r io.Reader) (byte, string, string, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, "", "", err
	}
	cmd := b[1]
	if cmd != 1 && cmd != 3 {
		return 0, "", "", fmt.Errorf("unsupported cmd %d", cmd)
	}
	var host string
	switch b[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, "", "", err
		}
		host = net.IP(ip).String()
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(r, n); err != nil {
			return 0, "", "", err
		}
		h := make([]byte, n[0])
		if _, err := io.ReadFull(r, h); err != nil {
			return 0, "", "", err
		}
		host = string(h)
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, "", "", err
		}
		host = net.IP(ip).String()
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, "", "", err
	}
	return cmd, host, fmt.Sprintf("%d", int(p[0])<<8|int(p[1])), nil
}

func pipe(dst, src net.Conn, done chan bool) {
	tuneConn(dst)
	tuneConn(src)
	buf := make([]byte, 65536)
	io.CopyBuffer(dst, src, buf)
	done <- true
}

// ─── HTTP CONNECT Proxy ────────────────────────────────────────────────────

func handleHTTPConnect(r *bufio.Reader, conn net.Conn, cl *ssh.Client) {
	mu.Lock()
	tunnelID++
	id := tunnelID
	mu.Unlock()
	defer conn.Close()
	tuneConn(conn)

	// Read the CONNECT request line + all headers up to \r\n\r\n
	reqLine := ""
	for i := 0; i < 256; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			msgDbg("HTTP", "#%d bad request: %v", id, err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if reqLine == "" {
			reqLine = line
		}
		if line == "" {
			break // end of headers
		}
	}

	if reqLine == "" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		msgDbg("HTTP", "#%d empty request", id)
		return
	}

	// Parse "CONNECT host:port HTTP/1.x"
	parts := strings.SplitN(reqLine, " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[0], "CONNECT") {
		resp := fmt.Sprintf("HTTP/1.1 400 Bad Request\r\n\r\n")
		conn.Write([]byte(resp))
		msgDbg("HTTP", "#%d bad verb: %s", id, parts[0])
		return
	}

	target := parts[1]
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		msgDbg("HTTP", "#%d bad target: %s", id, target)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		msgDbg("HTTP", "#%d bad port: %s", id, portStr)
		return
	}

	addr := conn.RemoteAddr().String()
	msgInfo("HTTP", "#%d %s CONNECT %s:%d", id, addr, host, port)

	if r, fallback := resolveWithFallback(host); fallback {
		msgDbg("HTTP", "#%d DNS → server-resolve %s", id, host)
	} else if r != host {
		msgDbg("HTTP", "#%d DNS %s → %s", id, host, r)
		host = r
	}
	targetConn, err := cl.Dial("tcp", net.JoinHostPort(host, portStr))
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		msgDbg("HTTP", "#%d %s → %s refused: %v", id, addr, target, err)
		return
	}
	defer targetConn.Close()
	tuneConn(targetConn)

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	h := host
	if len(h) > 50 {
		h = h[:50] + "..."
	}
	fmt.Println("  " + GRAY + DIM + time.Now().Format("15:04:05") + RST + " " + AMB + "➜" + RST + " #" + fmt.Sprint(id) + "  " + GRAY + DIM + addr + RST + " → " + CYN + strings.ToLower(h) + RST + ":" + BLD + portStr + RST)

	// After the HTTP 200, pump raw bytes bidirectionally
	done := make(chan bool, 2)
	go func() {
		io.Copy(targetConn, r)
		done <- true
	}()
	go func() {
		io.Copy(conn, targetConn)
		done <- true
	}()
	<-done
}

// ─── UDPGW PROTOCOL ─────────────────────────────────────────────────────────
//
// badvpn-udpgw protocol over TCP:
//   Frame: [2-byte LE length] [payload]
//   Payload: [flags:1] [conid:2 LE] [address] [data...]
//   IPv4 address: [ip:4][port:2 LE]
//   IPv6 address: [ip:16][port:2 LE]  (with flags |= 0x08)

const (
	udpgwFlagKeepAlive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3
)

type udpgwAddr struct {
	ip   net.IP
	port uint16
}

func encodeUDPGWAddr(host string, port int) *udpgwAddr {
	ip := net.ParseIP(host)
	a := &udpgwAddr{port: uint16(port)}
	if ip4 := ip.To4(); ip4 != nil {
		a.ip = ip4
	} else {
		a.ip = ip.To16()
	}
	return a
}

func (a *udpgwAddr) isIPv6() bool { return len(a.ip) == 16 }

func (a *udpgwAddr) marshal() []byte {
	if a.isIPv6() {
		b := make([]byte, 18)
		copy(b, a.ip)
		b[16] = byte(a.port)
		b[17] = byte(a.port >> 8)
		return b
	}
	b := make([]byte, 6)
	copy(b, a.ip)
	b[4] = byte(a.port)
	b[5] = byte(a.port >> 8)
	return b
}

func unmarshalUDPGWAddr(flags byte, data []byte) (*udpgwAddr, int) {
	if (flags & udpgwFlagIPv6) != 0 {
		if len(data) < 18 {
			return nil, 0
		}
		ip := make(net.IP, 16)
		copy(ip, data[:16])
		port := uint16(data[16]) | uint16(data[17])<<8
		return &udpgwAddr{ip: ip, port: port}, 18
	}
	if len(data) < 6 {
		return nil, 0
	}
	ip := make(net.IP, 4)
	copy(ip, data[:4])
	port := uint16(data[4]) | uint16(data[5])<<8
	return &udpgwAddr{ip: ip, port: port}, 6
}

func writeUDPGWMsg(conn net.Conn, flags byte, conid uint16, addr *udpgwAddr, data []byte) error {
	addrBytes := addr.marshal()
	totalLen := 3 + len(addrBytes) + len(data)
	buf := make([]byte, 2+totalLen)
	buf[0] = byte(totalLen)
	buf[1] = byte(totalLen >> 8)
	buf[2] = flags
	buf[3] = byte(conid)
	buf[4] = byte(conid >> 8)
	copy(buf[5:], addrBytes)
	copy(buf[5+len(addrBytes):], data)
	_, err := conn.Write(buf)
	return err
}

func readUDPGWMsg(conn net.Conn) (flags byte, conid uint16, addr *udpgwAddr, payload []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return
	}
	length := int(uint16(hdr[0]) | uint16(hdr[1])<<8)
	msg := make([]byte, length)
	if _, err = io.ReadFull(conn, msg); err != nil {
		return
	}
	if len(msg) < 3 {
		err = fmt.Errorf("udpgw msg too short")
		return
	}
	flags = msg[0]
	conid = uint16(msg[1]) | uint16(msg[2])<<8
	addr, n := unmarshalUDPGWAddr(flags, msg[3:])
	if addr == nil {
		err = fmt.Errorf("udpgw addr parse failed")
		return
	}
	payload = msg[3+n:]
	return
}

// ─── UDP ASSOCIATE (via udpgw) ─────────────────────────────────────────────

func handleUDPAssociate(conn net.Conn, cl *ssh.Client, id int, addr string) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		msgDbg("UDP", "#%d %s relay failed: %v", id, addr, err)
		return
	}
	defer udpConn.Close()

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip4 := localAddr.IP.To4()
	resp := []byte{5, 0, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3],
		byte(localAddr.Port >> 8), byte(localAddr.Port)}
	conn.Write(resp)

	msgInfo("UDP", "relay on 127.0.0.1:%d for client %s", localAddr.Port, addr)

	remote, err := cl.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", udpgwPort))
	if err != nil {
		msgWarn("UDP", "udpgw connect failed: %v", err)
		return
	}
	defer remote.Close()
	tuneConn(remote)

	conid := uint16(id)
	type response struct {
		addr    net.IP
		port    uint16
		data    []byte
	}
	respCh := make(chan response, 256)
	stopKeepalive := make(chan struct{})

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				writeUDPGWMsg(remote, udpgwFlagKeepAlive, 0,
					&udpgwAddr{ip: net.IPv4(0, 0, 0, 0), port: 0}, nil)
			case <-stopKeepalive:
				return
			}
		}
	}()

	go func() {
		for {
			flags, rconid, raddr, data, err := readUDPGWMsg(remote)
			if err != nil {
				close(respCh)
				return
			}
			if (flags & udpgwFlagKeepAlive) != 0 {
				continue
			}
			if rconid != conid {
				continue
			}
			cp := make([]byte, len(data))
			copy(cp, data)
			respCh <- response{raddr.ip, raddr.port, cp}
		}
	}()

	buf := make([]byte, 65535)
	var mu sync.Mutex
	var lastClient *net.UDPAddr

	go func() {
		for r := range respCh {
			mu.Lock()
			lc := lastClient
			mu.Unlock()
			if lc == nil {
				continue
			}
			wrapped := makeUDPResp(r.addr.String(), int(r.port), r.data)
			udpConn.WriteToUDP(wrapped, lc)
		}
	}()

	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		mu.Lock()
		lastClient = clientAddr
		mu.Unlock()

		host, port, payload := parseUDPHeader(buf[:n])
		if host == "" {
			continue
		}

		uaddr := encodeUDPGWAddr(host, port)
		flags := byte(0)
		if uaddr.isIPv6() {
			flags |= udpgwFlagIPv6
		}
		if err := writeUDPGWMsg(remote, flags, conid, uaddr, payload); err != nil {
			break
		}
	}

	close(stopKeepalive)
	msgDbg("UDP", "#%d %s relay closed", id, addr)
}

// ─── SOCKS5 UDP header helpers ─────────────────────────────────────────────

func parseUDPHeader(data []byte) (string, int, []byte) {
	if len(data) < 4 || data[2] != 0 {
		return "", 0, nil
	}
	pos := 3
	atype := data[pos]
	pos++
	switch atype {
	case 1:
		if len(data) < pos+6 {
			return "", 0, nil
		}
		return net.IP(data[pos:pos+4]).String(),
			int(data[pos+4])<<8 | int(data[pos+5]),
			data[pos+6:]
	case 3:
		if len(data) < pos+1 {
			return "", 0, nil
		}
		n := int(data[pos])
		pos++
		if len(data) < pos+n+2 {
			return "", 0, nil
		}
		return string(data[pos : pos+n]),
			int(data[pos+n])<<8 | int(data[pos+n+1]),
			data[pos+n+2:]
	case 4:
		if len(data) < pos+18 {
			return "", 0, nil
		}
		return net.IP(data[pos:pos+16]).String(),
			int(data[pos+16])<<8 | int(data[pos+17]),
			data[pos+18:]
	}
	return "", 0, nil
}

func makeUDPResp(host string, port int, data []byte) []byte {
	var atyp byte
	var addrBytes []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		atyp = 1
		addrBytes = ip4
	} else if ip16 := ip.To16(); ip16 != nil {
		atyp = 4
		addrBytes = ip16
	} else {
		atyp = 3
		addrBytes = []byte{byte(len(host))}
		addrBytes = append(addrBytes, []byte(host)...)
	}

	pkt := []byte{0, 0, 0, atyp}
	pkt = append(pkt, addrBytes...)
	pkt = append(pkt, byte(port>>8), byte(port))
	pkt = append(pkt, data...)
	return pkt
}

// ─── UI ────────────────────────────────────────────────────────────────────

const RST = "\033[0m"
const TEAL = "\033[1;38;5;45m"
const CYN = "\033[38;5;39m"
const GRN = "\033[38;5;42m"
const AMB = "\033[38;5;214m"
const RED = "\033[38;5;203m"
const GRAY = "\033[38;5;245m"
const DIM = "\033[2m"
const BLD = "\033[1m"
const PNK = "\033[38;5;213m"
const GLD = "\033[38;5;220m"

func clearScreen() { fmt.Print("\033[2J\033[H") }

const BW = 66

func top(color, label string) string {
	if label == "" {
		return "  " + color + "╔" + strings.Repeat("═", BW-2) + "╗" + RST
	}
	txt := " " + label + " "
	txtVis := 2 + visLen(label)
	dashes := BW - 2 - txtVis
	l := dashes / 2
	r := dashes - l
	return "  " + color + "╔" + strings.Repeat("═", l) + txt + color + strings.Repeat("═", r) + "╗" + RST
}

func bot(color string) string {
	return "  " + color + "╚" + strings.Repeat("═", BW-2) + "╝" + RST
}

func empty(color string) string {
	return "  " + color + "║" + RST + strings.Repeat(" ", BW-2) + color + "║" + RST
}

func boxLine(color string, parts ...string) string {
	vis := 0
	for _, p := range parts {
		vis += visLen(p)
	}
	pad := BW - 6 - vis
	if pad < 0 {
		pad = 0
	}
	line := "  " + color + "║" + RST + "  "
	for _, p := range parts {
		line += p
	}
	line += strings.Repeat(" ", pad) + "  " + color + "║" + RST
	return line
}

func visLen(s string) int {
	n := 0
	i := 0
	for i < len(s) {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		if size > 0 {
			n++
			i += size
		} else {
			i++
		}
	}
	return n
}

func padC(w int, text, color string) string {
	n := w - len(text)
	if n <= 0 {
		return color + text + RST
	}
	l := n / 2
	r := n - l
	return strings.Repeat(" ", l) + color + text + RST + strings.Repeat(" ", r)
}

func printBanner() {
	fmt.Println()
	fmt.Println(top(TEAL, ""))
	fmt.Println(boxLine(TEAL, padC(BW-6, "SSHT  V 1.0", TEAL+BLD)))
	fmt.Println(boxLine(TEAL, padC(BW-6, "made by ThisIsDara", GRAY)))
	fmt.Println(bot(TEAL))
	fmt.Println()
}

func printSummary(c *Config) {
	at := "password"
	if c.SSHKey != "" {
		at = "key"
	}
	if c.SSHPassword != "" && c.SSHKey != "" {
		at = "password + key"
	}
	sa := "no auth"
	if c.SOCKSUser != "" {
		sa = "user:" + c.SOCKSUser
	}

	fmt.Println(top(CYN, GLD+"Configuration"+RST))
	fmt.Println(empty(CYN))
	fmt.Println(boxLine(CYN,
		"  "+CYN+"SSH"+RST+"    "+BLD+c.SSHUser+"@"+c.SSHServer+":"+fmt.Sprint(c.SSHPort)+RST+
			"  "+GRAY+"("+at+")"+RST,
	))
	fmt.Println(boxLine(CYN,
		"  "+CYN+"SOCKS"+RST+"  "+BLD+"127.0.0.1:"+fmt.Sprint(c.SOCKSPort)+RST+
			"  "+GRAY+"("+sa+")"+RST,
	))
	udpLine := "  " + GRAY + "—" + RST
	if c.UDPGWPort > 0 {
		udpLine = "  " + CYN + "UDPGW" + RST + "  " + BLD + "port " + fmt.Sprint(c.UDPGWPort) + RST
	}
	fmt.Println(boxLine(CYN, udpLine))
	fmt.Println(boxLine(CYN,
		"  "+CYN+"KA"+RST+"     "+BLD+"30s TCP"+RST+"  "+GRAY+"·"+RST+"  "+BLD+"60s SSH"+RST,
	))
	fmt.Println(empty(CYN))
	fmt.Println(bot(CYN))
	fmt.Println()
}

func printReady(c *Config) {
	fmt.Println(top(GRN, GLD+"Ready"+RST))
	fmt.Println(empty(GRN))
	fmt.Println(boxLine(GRN,
		"  "+GLD+"●"+RST+"  "+BLD+"SOCKS5"+RST+"  "+TEAL+"127.0.0.1:"+fmt.Sprint(c.SOCKSPort)+RST,
	))
	if c.UDPGWPort > 0 {
		fmt.Println(boxLine(GRN,
			"  "+AMB+"◉"+RST+"  "+BLD+"UDPGW"+RST+"   "+TEAL+"127.0.0.1:"+fmt.Sprint(c.UDPGWPort)+RST,
		))
	}
	fmt.Println(boxLine(GRN,
		"  "+GRAY+"◇"+RST+"  "+DIM+"DNS"+RST+"    "+DIM+"local → 8.8.8.8 → server"+RST,
	))
	fmt.Println(boxLine(GRN,
		"  "+GRAY+"◆"+RST+"  "+DIM+"exit"+RST+"   "+DIM+"Ctrl+C"+RST,
	))
	fmt.Println(empty(GRN))
	fmt.Println(bot(GRN))
	fmt.Println()
}

// ─── Logging ───────────────────────────────────────────────────────────────

func msgInfo(t, m string, a ...interface{}) {
	fmt.Println("  " + GRAY + DIM + time.Now().Format("15:04:05") + RST + "  " + CYN + "●" + RST + "  " + CYN + t + RST + "  " + fmt.Sprintf(m, a...))
}
func msgOk(t, m string, a ...interface{}) {
	fmt.Println("  " + GRAY + DIM + time.Now().Format("15:04:05") + RST + "  " + GRN + "✔" + RST + "  " + GRN + t + RST + "  " + fmt.Sprintf(m, a...))
}
func msgWarn(t, m string, a ...interface{}) {
	fmt.Println("  " + GRAY + DIM + time.Now().Format("15:04:05") + RST + "  " + AMB + "⚠" + RST + "  " + AMB + t + RST + "  " + fmt.Sprintf(m, a...))
}
func msgFatal(t, m string, a ...interface{}) {
	fmt.Println("  " + GRAY + DIM + time.Now().Format("15:04:05") + RST + "  " + RED + "✘" + RST + "  " + RED + t + RST + "  " + fmt.Sprintf(m, a...))
	panic(nil)
}
func msgDbg(t, m string, a ...interface{}) {
	fmt.Println("  " + GRAY + DIM + time.Now().Format("15:04:05") + RST + "  " + GRAY + "·" + RST + "  " + DIM + GRAY + t + RST + "  " + DIM + GRAY + fmt.Sprintf(m, a...) + RST)
}

func pauseOnFatal() {
	if r := recover(); r != nil {
		fmt.Println()
		fmt.Println("  " + RED + strings.Repeat("═", BW-2) + RST)
		fmt.Println("  " + DIM + "  Press Enter to exit..." + RST)
		fmt.Println("  " + RED + strings.Repeat("═", BW-2) + RST)
		fmt.Scanln()
		os.Exit(1)
	}
}
