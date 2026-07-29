package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	livenessURL  = "https://127.0.0.1/health/live"
	expectedBody = `{"status":"ok"}` + "\n"
	maxBodyBytes = int64(64)
)

func main() {
	hostname := os.Getenv("OPSWARDEN_HOSTNAME")
	if hostname == "" {
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: hostname,
			// The probe reaches only this container's loopback listener. It
			// validates the exact liveness response instead of the public
			// certificate chain, which also permits Caddy's local test CA.
			InsecureSkipVerify: true, //nolint:gosec
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, livenessURL, nil,
	)
	if err != nil {
		os.Exit(1)
	}
	request.Host = hostname
	response, err := client.Do(request)
	if err != nil {
		os.Exit(1)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || response.StatusCode != http.StatusOK ||
		int64(len(body)) > maxBodyBytes ||
		string(body) != expectedBody {
		os.Exit(1)
	}
}
