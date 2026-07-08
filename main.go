package main

import (
	"encoding/base64"
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
