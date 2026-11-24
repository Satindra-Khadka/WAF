package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	upstream := getenv("UPSTREAM_URL", "http://localhost:3001")
	listen := getenv("LISTEN_ADDR", ":8080")

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s from %s", r.Method, r.URL.RequestURI(), r.RemoteAddr)
		proxy.ServeHTTP(w, r)
	})

	log.Printf("WAF proxy listening on %s -> %s", listen, upstream)
	log.Fatal(http.ListenAndServe(listen, handler))
}