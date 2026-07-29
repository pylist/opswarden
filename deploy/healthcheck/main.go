package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	livenessURL  = "http://127.0.0.1:8080/health/live"
	expectedBody = `{"status":"ok"}` + "\n"
	maxBodyBytes = int64(64)
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, livenessURL, nil)
	if err != nil {
		os.Exit(1)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		os.Exit(1)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	closeErr := response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK ||
		int64(len(body)) > maxBodyBytes ||
		closeErr != nil ||
		string(body) != expectedBody {
		os.Exit(1)
	}
}
