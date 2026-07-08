package main

import (
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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

	forwardTransport = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
)

func main() {
	proxyUser = os.Getenv("PROXY_USER")
	proxyPass = os.Getenv("PROXY_PASS")

	port := env("PORT", "7890")
	log.Printf("http proxy on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(handle)))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.Host)

	if proxyUser != "" && proxyPass != "" {
		if !checkAuth(r) {
			log.Printf("Auth failed")
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

func checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	return len(parts) == 2 && parts[0] == proxyUser && parts[1] == proxyPass
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	log.Printf("CONNECT to %s", r.Host)

	target, err := net.DialTimeout("tcp", r.Host, 30*time.Second)
	if err != nil {
		log.Printf("Dial error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer target.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Hijack not supported")
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Hijack error: %v", err)
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	log.Printf("Sending 200 Connection Established")
	_, err = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Write response error: %v", err)
		return
	}

	log.Printf("Starting relay")
	relay(client, target)
	log.Printf("Relay finished")
}

func handleForward(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	removeHopHeaders(r.Header)

	resp, err := forwardTransport.RoundTrip(r)
	if err != nil {
		log.Printf("Forward error %s %s: %v", r.Method, r.URL.String(), err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil && !isNormalClose(err) {
		log.Printf("Response copy error %s %s: %v", r.Method, r.URL.String(), err)
	}
}

func removeHopHeaders(h http.Header) {
	for _, f := range strings.Split(h.Get("Connection"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			h.Del(f)
		}
	}

	h.Del("Connection")
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authorization")
	h.Del("Keep-Alive")
	h.Del("TE")
	h.Del("Trailer")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
}

func relay(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()

		bufp := bufPool.Get().(*[]byte)
		n, err := io.CopyBuffer(dst, src, *bufp)
		bufPool.Put(bufp)

		if err != nil && !isNormalClose(err) {
			log.Printf("Copied %d bytes from %v to %v, err: %v", n, src.RemoteAddr(), dst.RemoteAddr(), err)
		} else {
			log.Printf("Copied %d bytes from %v to %v", n, src.RemoteAddr(), dst.RemoteAddr())
		}

		closeWrite(dst)
	}

	go cp(left, right)
	go cp(right, left)

	wg.Wait()
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}

	_ = conn.Close()
}

func isNormalClose(err error) bool {
	if err == nil || err == io.EOF || errors.Is(err, net.ErrClosed) {
		return true
	}

	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection")
}
