package main

import (
	"log"
	"net"
)

func handleConnection(conn *net.TCPConn) {
	log.Println("connection")
	defer conn.Close()

	buf := make([]byte, 4*1024)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				switch {
				case ne.Temporary():
					continue
				}
			}
			return
		}

		n, err = conn.Write(buf[:n])
		if err != nil {
			return
		}
	}
}

func handleListener(l *net.TCPListener) error {
	defer l.Close()
	for {
		conn, err := l.AcceptTCP()
		log.Println("listner")
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Temporary() {
					continue
				}
			}
			return err
		}

		go handleConnection(conn)
	}
}

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8888")
	if err != nil {
		log.Fatal(err)
	}

	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatal(err)
	}

	err = handleListener(l)
	if err != nil {
		log.Fatal(err)
	}
}
