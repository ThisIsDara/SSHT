# SSHT

[![GitHub](https://img.shields.io/badge/GitHub-ThisIsDara-blue?logo=github)](https://github.com/ThisIsDara/SSHT)

SSH Tunnel + SOCKS5/HTTP proxy with UDP relay

<img width="679" height="567" alt="image" src="https://github.com/user-attachments/assets/d283b846-f19d-46e2-b29f-7797a6b729e0" />


## 🚀 Features

### ✅ SSH Tunnel
- Password or key-based authentication with keyboard-interactive fallback
- TCP pre-check before connecting
- 30s TCP keepalive + 60s SSH keepalive to prevent NAT/firewall drops

### ✅ Proxy
- **SOCKS5** — Full TCP/UDP support with optional username/password auth
- **HTTP CONNECT** — Auto-detected alongside SOCKS5 on the same port

### ✅ UDP Relay (Optional)
- Full `badvpn-udpgw` protocol implementation
- 3-second keepalive pings to maintain the UDP tunnel

### ✅ Smart DNS
- Multi-tier fallback: local DNS → public DNS (8.8.8.8, 1.1.1.1) → server-side resolution

---


## ⚠️ Important

- **Avoid using `root` as SSH user** — use a regular user without any privileges.
- Check out **[ShahanPanel](https://github.com/HamedAp/ShahanPanel)**  a web panel for managing SSH accounts.

---
## Quick Start

### 📦 Requirements

- `badvpn-udpgw` running on your SSH server (optional, for UDP relay)

### 1 — Download or Build from Source

Download the latest binary from here 👉 [![Download](https://img.shields.io/badge/Download-2ea44f?style=for-the-badge&logo=github)](https://github.com/ThisIsDara/SSHT/releases)

Or build it yourself:

```
git clone https://github.com/ThisIsDara/SSHT.git
cd SSHT
go build -o SSHT .
```

### 2 — Configure

Edit `config.json`:

```json
{
  "ssh_server": "your.server.com",
  "ssh_port": 22,
  "ssh_user": "username",
  "ssh_key": "(Optional , you can leave this empty)",
  "ssh_password": "your_password",
  "socks_port": 1080,
  "socks_user": "",
  "socks_pass": "",
  "udpgw_port": 7300,
  "timeout_seconds": 10
}
```

### 3 — Run

**Windows:** Double-click `SSHT.exe` or run:

```
.\SSHT.exe
```

**Linux/macOS:**

```
chmod +x SSHT
./SSHT
```

### 4 — Use the Proxy

| Protocol | Address |
|---|---|
| SOCKS5 | `127.0.0.1:1080` |
| HTTP | `127.0.0.1:1080` |


---

## ⚙️ Options

| Field | Description |
|---|---|
| `ssh_key` | Path to SSH private key (empty = password auth) |
| `socks_user` / `socks_pass` | Optional SOCKS5 authentication |
| `udpgw_port` | Set to `0` to disable UDP relay |
| `timeout_seconds` | SSH connection timeout |

---



## License

MIT
