package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type tier int

const (
	TierOwner tier = iota
	TierAdmin
	TierPro
	TierBasic
)

func (a *Account) Tier() tier {
	switch a.Level {
	case "Owner":
		return TierOwner
	case "Admin":
		return TierAdmin
	case "Pro":
		return TierPro
	case "Basic":
		return TierBasic
	}
	return TierBasic
}

type Account struct {
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
	Expire   time.Time `json:"expire"`
	Level    string    `json:"level"`
}

func checkCreds(user, pass string) (bool, *Account) {
	raw, err := os.ReadFile("users.json")
	if err != nil {
		return false, nil
	}
	var accts []Account
	json.Unmarshal(raw, &accts)
	for _, a := range accts {
		if a.Username == user && a.Password == pass && a.Expire.After(time.Now()) {
			return true, &a
		}
	}
	return false, nil
}

func titleEsc(t string) string {
	return "\u001B]0;" + t + "\a"
}

func (s *session) setHeader(t string) {
	s.conn.Write([]byte(titleEsc(t)))
}

func writeTitle(conn net.Conn, t string) {
	conn.Write([]byte(fmt.Sprintf("\033]0;%s\007", t)))
}

func randStr(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}
