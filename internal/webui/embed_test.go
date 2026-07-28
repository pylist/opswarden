package webui

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesIndexAtRoot(t *testing.T) {
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("got status %d", response.Code)
	}
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `<div id="root"></div>`) {
		t.Fatalf("root shell is missing: %s", body)
	}
}

func TestHandlerFallsBackToIndexForClientRoute(t *testing.T) {
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/settings", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("got status %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), `<div id="root"></div>`) {
		t.Fatalf("fallback did not serve the root shell: %s", response.Body.String())
	}
}

func TestHandlerServesEmbeddedStaticAsset(t *testing.T) {
	entries, err := fs.ReadDir(assets, "dist/assets")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no built assets are embedded")
	}

	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/assets/"+entries[0].Name(), nil))

	if response.Code != http.StatusOK {
		t.Fatalf("got status %d", response.Code)
	}
	if response.Body.Len() == 0 {
		t.Fatal("embedded asset response is empty")
	}
}
