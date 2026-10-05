package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// dialSOCKS5 sends domain names to the proxy, so the local resolver never sees
// destination names. A failed proxy handshake never falls back to direct TCP.
//
// The greeting offers username/password authentication (RFC 1929) as well as
// no authentication. Tor selects username/password when both are offered and,
// with IsolateSOCKSAuth (on by default), never shares a circuit between streams
// that presented different credentials. The inference client presents a fresh
// credential on every dial, and NewClient disables HTTP keep-alives, so every
// HTTP request is a new connection and therefore its own circuit; that
// dependency is what turns per-connection isolation into per-request isolation.
func dialSOCKS5(ctx context.Context, proxyAddress, network, destination, username, password string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("SOCKS5 requires TCP")
	}
	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, errors.New("invalid SOCKS5 destination")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid SOCKS5 destination port")
	}
	addressType := byte(3)
	address := []byte(host)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addressType, address = 1, ip4
		} else {
			addressType, address = 4, ip.To16()
		}
	} else if len(address) == 0 || len(address) > 255 {
		return nil, errors.New("invalid SOCKS5 destination name")
	}
	if len(username) == 0 || len(username) > 255 || len(password) == 0 || len(password) > 255 {
		return nil, errors.New("invalid SOCKS5 credential")
	}
	conn, err := (&net.Dialer{Timeout: 20 * time.Second}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, errors.New("SOCKS5 proxy unavailable")
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := io.Copy(conn, bytes.NewReader([]byte{5, 2, 0, 2})); err != nil {
		return nil, errors.New("SOCKS5 greeting failed")
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:2]); err != nil || reply[0] != 5 {
		return nil, errors.New("SOCKS5 greeting rejected")
	}
	switch reply[1] {
	case 0:
	case 2:
		auth := append([]byte{1, byte(len(username))}, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if _, err := io.Copy(conn, bytes.NewReader(auth)); err != nil {
			return nil, errors.New("SOCKS5 authentication failed")
		}
		if _, err := io.ReadFull(conn, reply[:2]); err != nil || reply[0] != 1 || reply[1] != 0 {
			return nil, errors.New("SOCKS5 proxy rejected credentials")
		}
	default:
		return nil, errors.New("SOCKS5 proxy accepted neither offered authentication method")
	}
	request := []byte{5, 1, 0, addressType}
	if addressType == 3 {
		request = append(request, byte(len(address)))
	}
	request = append(request, address...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := io.Copy(conn, bytes.NewReader(request)); err != nil {
		return nil, errors.New("SOCKS5 connect request failed")
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, errors.New("SOCKS5 connect failed")
	}
	remaining := 0
	switch reply[3] {
	case 1:
		remaining = 4
	case 4:
		remaining = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, errors.New("SOCKS5 connect reply truncated")
		}
		remaining = int(length[0])
	default:
		return nil, errors.New("SOCKS5 connect reply invalid")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(remaining+2)); err != nil {
		return nil, errors.New("SOCKS5 connect reply truncated")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return conn, nil
}

// socks5Credential returns a random username and password for one connection.
// Tor uses them only as a circuit isolation key; nothing verifies them.
func socks5Credential() (username, password string, err error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", "", errors.New("SOCKS5 credential generation failed")
	}
	return hex.EncodeToString(secret[:16]), hex.EncodeToString(secret[16:]), nil
}
