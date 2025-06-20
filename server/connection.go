package main

import (
	"net"
	"time"
)

func HandleConnection(conn net.Conn) error {
	time.Sleep(10 * time.Second)

	return nil
}
