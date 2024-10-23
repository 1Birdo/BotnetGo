# Botnet Control and Command (CnC) Server

## Overview
This project implements a simple Botnet Control and Command (CnC) server in Go, enabling users to manage connected bots and execute various network attack commands.

## Features
- **User Authentication**: Secure login and credential management.
- **Bot Management**: Connect and manage multiple bots.
- **Attack Execution**: Send commands to bots for executing different types of network attacks.
- **Logging**: Track bot connections and actions.

## Prerequisites
- Go 1.18 or higher
- Terminal/command line interface
- Basic understanding of Go and network programming

## Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/Birdo1221/BotnetGo.git
   cd BotnetGo
   ```

2. **Install dependencies**:
   ```bash
   go mod tidy
   ```

3. **Build the project**:
   ```bash
   go build -o botnet
   ```

4. **Run the server**:
   ```bash
   ./botnet
   ```

## Configuration
Edit the constants in `main.go` to configure:
- **User and Bot Server IPs**: Adjust `USER_SERVER_IP` and `BOT_SERVER_IP`.
- **Server Ports**: Modify `USER_SERVER_PORT` and `BOT_SERVER_PORT`.

## Usage
- Start the server and connect your bots.
- Use the CLI to log in and execute commands.
  ### e.g. Termum, Mobaxterm or Putty
- Example command to start an attack:
  ```bash
  !tcpflood <target_ip> <target_port> <duration>
  ```

## Disclaimer

#  ```This project is for educational purposes only. Ensure you have permission before testing any network security tools on remote servers. I bear no responsibility or obligation to anyone using this for malicious purposes. ```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
