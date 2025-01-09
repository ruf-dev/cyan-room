package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/sirupsen/logrus"
	"go.redsock.ru/rerrors"
	"golang.org/x/net/proxy"

	"go.redsock.ru/ruf/cyan-room/internal/config"
)

type server struct {
	port string
}

func New(cfg config.Config) (*server, error) {
	s := &server{
		port: strconv.Itoa(cfg.Environment.ProxyServerPort),
	}

	return s, nil
}

func (s server) Start() error {
	// Listen on a specific port
	listener, err := net.Listen("tcp", "0.0.0.0:"+s.port)
	if err != nil {
		return rerrors.Wrap(err, "Error starting the proxy server")
	}
	defer listener.Close()
	logrus.Info("SOCKS5 Proxy server is running on port " + s.port)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			logrus.Error("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Use the x/net/proxy package to handle SOCKS5 connections
	dialer := proxy.FromEnvironment().Dial
	targetAddr, err := parseClientRequest(clientConn)
	if err != nil {
		logrus.Errorf("Error parsing target addr: %v", err)
		return
	}
	// Forward traffic
	target, err := dialer("tcp", targetAddr) // Example target server
	if err != nil {
		logrus.Errorf("Error connecting to target: %v", err)
		return
	}
	defer target.Close()

	// Relay data between client and target server
	go func() { _, _ = io.Copy(target, clientConn) }()
	_, _ = io.Copy(clientConn, target)
}

func parseClientRequest(conn net.Conn) (string, error) {
	// Read the initial handshake from the client
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read handshake: %v", err)
	}

	// Validate SOCKS5 version
	if n < 2 || buf[0] != 0x05 {
		return "", errors.New("invalid SOCKS version")
	}

	// Respond to the handshake with "no authentication required"
	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		return "", fmt.Errorf("failed to write handshake response: %v", err)
	}

	// Read the SOCKS5 request
	n, err = conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read client request: %v", err)
	}

	// Validate request length
	if n < 10 {
		return "", errors.New("invalid SOCKS request")
	}

	// Extract the command and address type
	cmd := buf[1]
	addrType := buf[3]

	if cmd != 0x01 { // 0x01 = CONNECT command
		return "", errors.New("unsupported command; only CONNECT is supported")
	}

	// Parse the target address
	var targetAddr string
	var targetPort uint16

	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			return "", errors.New("invalid IPv4 address length")
		}
		targetAddr = net.IP(buf[4:8]).String()
		targetPort = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // Domain name
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return "", errors.New("invalid domain name length")
		}
		targetAddr = string(buf[5 : 5+domainLen])
		targetPort = binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])
	case 0x04: // IPv6
		if n < 22 {
			return "", errors.New("invalid IPv6 address length")
		}
		targetAddr = net.IP(buf[4:20]).String()
		targetPort = binary.BigEndian.Uint16(buf[20:22])
	default:
		return "", errors.New("unsupported address type")
	}

	// Respond with a success message
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return "", fmt.Errorf("failed to write success response: %v", err)
	}

	// Return the parsed target address and port
	return fmt.Sprintf("%s:%d", targetAddr, targetPort), nil
}
