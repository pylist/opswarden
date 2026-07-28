package app

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opswarden/internal/config"
)

func TestNewCreatesDatabaseInConfiguredDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	masterKeyFile := writeMasterKey(t)
	application, err := New(config.Config{
		ListenAddr:    "127.0.0.1:0",
		DataDir:       dataDir,
		MasterKeyFile: masterKeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if application.db == nil {
		t.Fatal("application database is nil")
	}
	t.Cleanup(func() {
		if err := application.db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	if _, err := os.Stat(filepath.Join(dataDir, "opswarden.db")); err != nil {
		t.Fatalf("stat application database: %v", err)
	}
}

func TestNewRejectsMissingMasterKey(t *testing.T) {
	application, err := New(config.Config{
		ListenAddr:    "127.0.0.1:0",
		DataDir:       filepath.Join(t.TempDir(), "data"),
		MasterKeyFile: filepath.Join(t.TempDir(), "missing.key"),
	})
	if err == nil || application != nil {
		t.Fatalf("application=%v error=%v", application, err)
	}
}

func TestNewConfiguresDefensiveHTTPServerLimits(t *testing.T) {
	application, err := New(config.Config{
		ListenAddr: "127.0.0.1:0", DataDir: t.TempDir(),
		MasterKeyFile: writeMasterKey(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	server := application.server
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 ||
		server.WriteTimeout <= 0 || server.IdleTimeout <= 0 ||
		server.MaxHeaderBytes <= 0 || server.MaxHeaderBytes > 64<<10 {
		t.Fatalf(
			"unsafe server limits: readHeader=%s read=%s write=%s idle=%s headers=%d",
			server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout,
			server.IdleTimeout, server.MaxHeaderBytes,
		)
	}
}

func TestNewMountsProtectedMCPRoute(t *testing.T) {
	application, err := New(config.Config{
		ListenAddr: "127.0.0.1:0", DataDir: t.TempDir(),
		MasterKeyFile: writeMasterKey(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	request := httptest.NewRequest(
		http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("missing MCP security headers: %v", response.Header())
	}
}

func writeMasterKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.key")
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	if err := os.WriteFile(
		path, []byte(base64.StdEncoding.EncodeToString(raw)), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	clear(raw)
	return path
}

func TestRunWaitsForInFlightRequestAfterContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	application := &App{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-release
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	application.server = &http.Server{Addr: addr, Handler: application.handler}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- application.Run(ctx) }()

	requestErr := make(chan error, 1)
	go func() {
		_, err := http.Get("http://" + addr)
		requestErr <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the handler")
	}

	cancel()
	select {
	case err := <-runErr:
		t.Fatalf("Run returned before the in-flight request completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not finish after the in-flight request completed")
	}

	if err := <-requestErr; err != nil {
		t.Fatal(err)
	}
}
