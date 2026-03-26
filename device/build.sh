#!/bin/sh
set -e

FLAGS="-ldflags=-s -w"
SRC="bot.go"

build() {
    GOOS=$1 GOARCH=$2 GOARM=$3 go build -ldflags="-s -w" "$SRC"
    mv bot "$4"
    echo "built $4"
}

build linux 386 "" x86
build linux arm 7 armv7l
build linux arm 5 armv5l
build linux arm64 "" armv8l
build linux mips "" mips
build linux mipsle "" mipsel

echo "done"
