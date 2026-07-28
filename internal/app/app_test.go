package app

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

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
