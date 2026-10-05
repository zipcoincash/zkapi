package relay

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// socks5Exchange records what one client connection sent to the fake proxy.
type socks5Exchange struct {
	greeting           []byte
	username, password string
	destination        string
	closed             bool // the client closed the connection after a handshake failure
}

// fakeSOCKS5 accepts connections and answers each handshake with the given
// method selection and (for method 2) RFC 1929 status, then connects.
func fakeSOCKS5(t *testing.T, method, status byte) (net.Listener, <-chan socks5Exchange) {
	t.Helper()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Close() })
	seen := make(chan socks5Exchange, 4)
	go func() {
		for {
			conn, err := proxy.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				seen <- serveSOCKS5(conn, method, status)
			}()
		}
	}()
	return proxy, seen
}

func serveSOCKS5(conn net.Conn, method, status byte) (x socks5Exchange) {
	readClosed := func() { _, err := conn.Read(make([]byte, 1)); x.closed = err == io.EOF }
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 {
		return x
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return x
	}
	x.greeting = append(header, methods...)
	_, _ = conn.Write([]byte{5, method})
	switch method {
	case 0:
	case 2:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil || length[0] != 1 {
			return x
		}
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return x
		}
		username := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, username); err != nil {
			return x
		}
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return x
		}
		password := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, password); err != nil {
			return x
		}
		x.username, x.password = string(username), string(password)
		_, _ = conn.Write([]byte{1, status})
		if status != 0 {
			readClosed()
			return x
		}
	default:
		readClosed()
		return x
	}
	request := make([]byte, 5)
	if _, err := io.ReadFull(conn, request); err != nil || string(request[:4]) != string([]byte{5, 1, 0, 3}) {
		return x
	}
	nameAndPort := make([]byte, int(request[4])+2)
	if _, err := io.ReadFull(conn, nameAndPort); err != nil {
		return x
	}
	x.destination = string(nameAndPort[:len(nameAndPort)-2])
	_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	_, _ = conn.Write([]byte("connected"))
	return x
}

func dialConnected(t *testing.T, proxy net.Listener) {
	t.Helper()
	dial, err := destinationDialer("socks5://" + proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), "tcp", "unresolved.example.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := make([]byte, len("connected"))
	if _, err := io.ReadFull(conn, data); err != nil || string(data) != "connected" {
		t.Fatalf("SOCKS5 connection unusable: %q, %v", data, err)
	}
}

func TestSOCKS5SendsDestinationNameToProxyAndFailsClosed(t *testing.T) {
	proxy, seen := fakeSOCKS5(t, 0, 0)
	dialConnected(t, proxy)
	if x := <-seen; x.destination != "unresolved.example.invalid" || x.username != "" {
		t.Fatalf("destination DNS did not stay with proxy: %q", x.destination)
	}
	dial, err := destinationDialer("socks5://" + proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxy.Close()
	if conn, err := dial(context.Background(), "tcp", "unresolved.example.invalid:443"); err == nil {
		conn.Close()
		t.Fatal("proxy outage fell back to direct TCP")
	}
}

func TestSOCKS5PresentsFreshCredentialsPerConnection(t *testing.T) {
	proxy, seen := fakeSOCKS5(t, 2, 0)
	dialConnected(t, proxy)
	dialConnected(t, proxy)
	first, second := <-seen, <-seen
	for _, x := range []socks5Exchange{first, second} {
		if string(x.greeting) != string([]byte{5, 2, 0, 2}) {
			t.Fatalf("greeting did not offer no-auth and username/password: %v", x.greeting)
		}
		for _, field := range []string{x.username, x.password} {
			if raw, err := hex.DecodeString(field); err != nil || len(raw) != 16 {
				t.Fatalf("credential is not 16 random hex-encoded bytes: %q", field)
			}
		}
		if x.destination != "unresolved.example.invalid" {
			t.Fatalf("authenticated connect lost destination: %q", x.destination)
		}
	}
	if first.username == second.username || first.password == second.password {
		t.Fatalf("consecutive connections shared a credential: %q %q", first.username, second.username)
	}
}

func TestCompanionBridgeSharesOneCredentialPerProcess(t *testing.T) {
	proxy, seen := fakeSOCKS5(t, 2, 0)
	bridge, err := StartConnectProxy(context.Background(), "socks5://"+proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	bridgeURL, _ := url.Parse(bridge.URL)
	password, _ := bridgeURL.User.Password()
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("oa:"+password))
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", bridgeURL.Host)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(conn, "CONNECT unresolved.example.invalid:443 HTTP/1.1\r\nHost: unresolved.example.invalid:443\r\nProxy-Authorization: "+auth+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatal("CONNECT through SOCKS5 failed", err)
		}
		resp.Body.Close()
		conn.Close()
	}
	first, second := <-seen, <-seen
	if first.username == "" || first.username != second.username || first.password != second.password {
		t.Fatalf("companion connections did not share one credential: %q %q", first.username, second.username)
	}
	inference, err := destinationDialer("socks5://" + proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := inference(context.Background(), "tcp", "unresolved.example.invalid:443"); err == nil {
		conn.Close()
	}
	if x := <-seen; x.username == first.username {
		t.Fatal("inference traffic shared the companion credential")
	}
}

func TestSOCKS5FailsClosedWhenHandshakeIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name           string
		method, status byte
	}{
		{"no acceptable method", 0xff, 0},
		{"unoffered method", 1, 0},
		{"credentials rejected", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy, seen := fakeSOCKS5(t, tc.method, tc.status)
			dial, err := destinationDialer("socks5://" + proxy.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dial(context.Background(), "tcp", "unresolved.example.invalid:443")
			if err == nil {
				conn.Close()
				t.Fatal("rejected handshake returned a connection")
			}
			if x := <-seen; !x.closed || x.destination != "" {
				t.Fatalf("client did not close after rejection: closed=%v destination=%q", x.closed, x.destination)
			}
		})
	}
}

func TestSOCKS5RequiresLoopbackProxy(t *testing.T) {
	for _, endpoint := range []string{"socks5://example.com:9050", "socks5://127.0.0.1", "socks5://127.0.0.1:0", "socks5://user:pass@127.0.0.1:9050", "socks5://127.0.0.1:9050/path", "socks5://127.0.0.1:9050/?x=1"} {
		if _, err := NewClient(endpoint); err == nil {
			t.Fatalf("accepted unsafe SOCKS5 endpoint %q", endpoint)
		}
	}
}

// TestLiveTorSOCKS5 needs a running Tor client, for example the one started by
// zkapi-serve-tor.sh. Five requests through the client must each leave Tor,
// and with per-connection credentials they must not all share one exit.
func TestLiveTorSOCKS5(t *testing.T) {
	endpoint := os.Getenv("ZKAPI_LIVE_TOR_SOCKS5")
	if endpoint == "" {
		t.Skip("set ZKAPI_LIVE_TOR_SOCKS5 for a live Tor check")
	}
	client, err := NewClient(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client.Timeout = 45 * time.Second
	exits := map[string]int{}
	for i := 0; i < 5; i++ {
		started := time.Now()
		response, err := client.Get("https://check.torproject.org/api/ip")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || !strings.Contains(string(body), `"IsTor":true`) {
			t.Fatalf("Tor check failed: status=%d body=%q err=%v", response.StatusCode, body, err)
		}
		exit := strings.TrimSpace(string(body))
		exits[exit]++
		t.Logf("request %d: %s in %.1fs", i+1, exit, time.Since(started).Seconds())
	}
	if len(exits) < 2 {
		t.Fatalf("five requests used a single exit: %v", exits)
	}
}
