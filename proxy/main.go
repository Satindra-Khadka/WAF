package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

const maxBodyBytes = 1 << 20 // 1 MiB

type inspectRequest struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	ClientIP string            `json:"client_ip"`
}

type inspectResponse struct {
	Decision     string   `json:"decision"`
	Score        float64  `json:"score"`
	MatchedRules []string `json:"matched_rules"`
	Reason       string   `json:"reason"`
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func callDetector(ctx context.Context, client *http.Client, detectorURL string, payload inspectRequest) (*inspectResponse, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, detectorURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("detector returned status %d", resp.StatusCode)
	}

	var out inspectResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func main() {
	upstream := getenv("UPSTREAM_URL", "http://localhost:3001")
	detectorURL := getenv("DETECTOR_URL", "http://localhost:8000/inspect")
	listen := getenv("LISTEN_ADDR", ":8080")

	timeout, err := time.ParseDuration(getenv("DETECTOR_TIMEOUT", "500ms"))
	if err != nil {
		log.Fatalf("invalid DETECTOR_TIMEOUT: %v", err)
	}

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	client := &http.Client{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Read the body (size-limited), then restore it so it can still be forwarded
		var bodyBytes []byte
		if r.Body != nil {
			var readErr error
			bodyBytes, readErr = io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
			if readErr != nil {
				http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body.Close()
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))

		// 2. Build the inspection payload
		headers := make(map[string]string, len(r.Header))
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		payload := inspectRequest{
			Method:   r.Method,
			Path:     r.URL.Path,
			Query:    r.URL.RawQuery,
			Headers:  headers,
			Body:     string(bodyBytes),
			ClientIP: clientIP,
		}

		// 3. Ask the detector, with a timeout
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		result, err := callDetector(ctx, client, detectorURL, payload)
		if err != nil {
			// Fail closed: no reliable inspection result means no forwarding
			log.Printf("FAIL-CLOSED %s %s: %v", r.Method, r.URL.RequestURI(), err)
			http.Error(w, "inspection unavailable", http.StatusServiceUnavailable)
			return
		}

		// 4. Enforce the decision
		if result.Decision == "block" {
			log.Printf("BLOCK %s %s rules=%v", r.Method, r.URL.RequestURI(), result.MatchedRules)
			http.Error(w, "Blocked by WAF", http.StatusForbidden)
			return
		}

		log.Printf("ALLOW %s %s", r.Method, r.URL.RequestURI())
		proxy.ServeHTTP(w, r)
	})

	log.Printf("WAF proxy listening on %s -> %s (detector: %s)", listen, upstream, detectorURL)
	log.Fatal(http.ListenAndServe(listen, handler))
}
