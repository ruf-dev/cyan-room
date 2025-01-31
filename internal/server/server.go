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

// Allowed users (username:password)
var authUsers = map[string]string{
	"user1": "password123",
	"user2": "securepass",
}

// Whitelisted IPs
var whitelistedIPs = map[string]bool{
	"192.168.1.100": true, // Example internal IP
	"203.0.113.42":  true, // Example public IP
}

type Server struct {
	port string
}

func New(cfg config.Config) (*Server, error) {
	s := &Server{
		port: strconv.Itoa(cfg.Environment.ProxyServerPort),
	}

	return s, nil
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", "127.0.0.1:"+s.port) // Bind to localhost
	if err != nil {
		return rerrors.Wrap(err, "Error starting the proxy server")
	}
	defer listener.Close()
	logrus.Info("Private SOCKS5 Proxy running on 127.0.0.1:" + s.port)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			logrus.Errorf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Restrict access based on IP (optional)
	clientIP, _, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	if !whitelistedIPs[clientIP] {
		logrus.Warnf("Blocked unauthorized IP: %s", clientIP)
		clientConn.Close()
		return
	}

	// Authenticate user
	if err := authenticateClient(clientConn); err != nil {
		logrus.Warnf("Authentication failed: %v", err)
		clientConn.Close()
		return
	}

	// Handle SOCKS5 request
	targetAddr, err := parseClientRequest(clientConn)
	if err != nil {
		logrus.Errorf("Error parsing target addr: %v", err)
		return
	}

	dialer := proxy.FromEnvironment().Dial
	target, err := dialer("tcp", targetAddr)
	if err != nil {
		logrus.Errorf("Error connecting to target: %v", err)
		return
	}
	defer target.Close()

	// Relay data
	go io.Copy(target, clientConn)
	io.Copy(clientConn, target)
}

// Authenticate client using username/password
func authenticateClient(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return err
	}

	// Ensure SOCKS5 and username/password authentication (0x02)
	if buf[0] != 0x05 || buf[1] != 0x02 {
		return errors.New("invalid SOCKS5 handshake")
	}

	// Respond to authentication method selection
	conn.Write([]byte{0x05, 0x02})

	// Read authentication request
	buf = make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x01 {
		return errors.New("invalid authentication request")
	}

	// Extract username and password
	ulen := int(buf[1])
	if n < 2+ulen+1 {
		return errors.New("invalid username length")
	}
	username := string(buf[2 : 2+ulen])

	plen := int(buf[2+ulen])
	if n < 3+ulen+plen {
		return errors.New("invalid password length")
	}
	password := string(buf[3+ulen : 3+ulen+plen])

	// Verify credentials
	if storedPass, ok := authUsers[username]; !ok || storedPass != password {
		conn.Write([]byte{0x01, 0x01}) // Authentication failed
		return errors.New("authentication failed")
	}

	conn.Write([]byte{0x01, 0x00}) // Authentication success
	return nil
}

// Parse SOCKS5 client request
func parseClientRequest(conn net.Conn) (string, error) {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read request: %v", err)
	}

	if n < 10 || buf[0] != 0x05 || buf[1] != 0x01 {
		return "", errors.New("invalid SOCKS5 request")
	}

	var targetAddr string
	var targetPort uint16

	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return "", errors.New("invalid IPv4 request")
		}
		targetAddr = net.IP(buf[4:8]).String()
		targetPort = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // Domain name
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return "", errors.New("invalid domain request")
		}
		targetAddr = string(buf[5 : 5+domainLen])
		targetPort = binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])
	case 0x04: // IPv6
		if n < 22 {
			return "", errors.New("invalid IPv6 request")
		}
		targetAddr = net.IP(buf[4:20]).String()
		targetPort = binary.BigEndian.Uint16(buf[20:22])
	default:
		return "", errors.New("unsupported address type")
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return fmt.Sprintf("%s:%d", targetAddr, targetPort), nil
}
