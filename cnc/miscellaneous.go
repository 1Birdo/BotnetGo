package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type level int

const (
	Owner level = iota
	Admin
	Pro
	Basic
)

func (user *User) GetLevel() level {
	switch user.Level {
	case "Owner":
		return Owner
	case "Admin":
		return Admin
	case "Pro":
		return Pro
	case "Basic":
		return Basic
	default:
		return Basic // Default level
	}
}

type User struct {
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
	Expire   time.Time `json:"expire"`
	Level    string    `json:"level"` // Handle level as a string
}

func AuthUser(username string, password string) (bool, *User) {
	users := []User{}
	usersFile, err := os.ReadFile("users.json")
	if err != nil {
		return false, nil
	}
	json.Unmarshal(usersFile, &users)
	for _, user := range users {
		if user.Username == username && user.Password == password {
			if user.Expire.After(time.Now()) {
				return true, &user
			}
		}
	}
	return false, nil
}

func getConsoleTitleAnsi(title string) string {
	return "\u001B]0;" + title + "\a"
}

func (c *client) setConsoleTitle(title string) {
	c.conn.Write([]byte(getConsoleTitleAnsi(title)))
}

func setTitle(conn net.Conn, title string) {
	// Send the escape sequence to set the window title
	titleSequence := fmt.Sprintf("\033]0;%s\007", title)
	conn.Write([]byte(titleSequence))
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err // return an error if reading fails
	}

	for i := range b {
		b[i] = letterBytes[b[i]%byte(len(letterBytes))]
	}

	return string(b), nil
}
