package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

var (
	proxyUser string
	proxyPass string
)

func main() {
	proxyUser = os.Getenv("PROXY_USER")
	proxyPass = os.Getenv("PROXY_PASS")

	port := env("PORT", "7890")
	go listenSOCKS5(":" + port)

	httpPort := env("HTTP_PORT", "7891")
	log.Printf("SOCKS5 on :%s, HTTP on :%s", port, httpPort)
	log.Fatal(http.ListenAndServe(":"+httpPort, http.HandlerFunc(httpProxy)))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func authEnabled() bool {
	return proxyUser != "" && proxyPass != ""
}

// ==================== SOCKS5 ====================

func listenSOCKS5(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("socks5 listen: %v", err)
	}
	log.Printf("socks5 listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("socks5 accept: %v", err)
			continue
		}
		go handleSOCKS5(conn)
	}
}

func handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)

	// 握手: VER NMETHODS METHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	if authEnabled() {
		// 要求用户名/密码认证 (0x02)
		conn.Write([]byte{0x05, 0x02})

		// 认证: VER ULEN USER PLEN PASS
		authHdr := make([]byte, 2)
		if _, err := io.ReadFull(br, authHdr); err != nil || authHdr[0] != 0x01 {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		user := make([]byte, authHdr[1])
		if _, err := io.ReadFull(br, user); err != nil {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		passLen, err := br.ReadByte()
		if err != nil {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		pass := make([]byte, passLen)
		if _, err := io.ReadFull(br, pass); err != nil {
			conn.Write([]byte{0x01, 0x01})
			return
		}

		if string(user) != proxyUser || string(pass) != proxyPass {
			conn.Write([]byte{0x01, 0x01}) // 认证失败
			return
		}
		conn.Write([]byte{0x01, 0x00}) // 认证成功
	} else {
		// 无需认证
		conn.Write([]byte{0x05, 0x00})
	}

	// 请求: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		socksReply(conn, 0x07)
		return
	}

	host, err := readAddr(br, req[3])
	if err != nil {
		socksReply(conn, 0x01)
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		socksReply(conn, 0x01)
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	dst, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		socksReply(conn, 0x04)
		return
	}
	defer dst.Close()

	socksReply(conn, 0x00)
	relay(conn, dst)
}

func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case 0x03:
		lenBuf, err := bufio.NewReaderSize(r, 1).ReadByte()
		if err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf)
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	default:
		return "", fmt.Errorf("unknown atyp: %d", atyp)
	}
}

func socksReply(conn net.Conn, rep byte) {
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// ==================== HTTP Proxy ====================

func httpProxy(w http.ResponseWriter, r *http.Request) {
	if authEnabled() {
		if !checkHTTPAuth(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
			http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
			return
		}
	}

	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
	} else {
		handleForward(w, r)
	}
}

func checkHTTPAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[0] == proxyUser && parts[1] == proxyPass
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	target, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		target.Close()
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		target.Close()
		return
	}

	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	relay(client, target)
}

func handleForward(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ==================== Relay ====================

func relay(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		bufp := bufPool.Get().(*[]byte)
		io.CopyBuffer(dst, src, *bufp)
		bufPool.Put(bufp)
		dst.Close()
	}

	go cp(left, right)
	go cp(right, left)

	wg.Wait()
}
