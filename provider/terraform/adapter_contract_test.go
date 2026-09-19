package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reply serves one fixed adapter reply for every request.
func reply(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// refusedURL is a loopback address nothing listens on: the shape of a tunnel
// that is down.
func refusedURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr
}

func get(baseURL string) error {
	c := &client{baseURL: baseURL, http: &http.Client{}}
	_, err := c.call(context.Background(), "/uci/get", map[string]any{"config": "network", "section": "lan"})
	return err
}

// Only the device's own "not found" means a section is gone. Every other
// failure observed nothing about the section, and Read must keep state.
func TestOnlyTheDeviceCanSayASectionIsAbsent(t *testing.T) {
	rows := []struct {
		name   string
		err    func(t *testing.T) error
		absent bool
	}{
		{"device answered ubus status 4", func(*testing.T) error {
			s := reply(404, `{"error":"ubus status 4: not found"}`)
			defer s.Close()
			return get(s.URL)
		}, true},
		{"tunnel down: connection refused", func(t *testing.T) error {
			return get(refusedURL(t))
		}, false},
		{"adapter has no route for the path", func(*testing.T) error {
			s := reply(404, `{"error":"no ubus operation at /uci/get; the adapter serves only what the façade describes"}`)
			defer s.Close()
			return get(s.URL)
		}, false},
		{"device has no uci object", func(*testing.T) error {
			s := reply(404, `{"error":"the device has no ubus object at \"uci\""}`)
			defer s.Close()
			return get(s.URL)
		}, false},
		{"adapter could not reach ubusd", func(*testing.T) error {
			s := reply(502, `{"error":"connecting to ubusd: No such file or directory"}`)
			defer s.Close()
			return get(s.URL)
		}, false},
		{"permission denied", func(*testing.T) error {
			s := reply(403, `{"error":"ubus status 6: permission denied"}`)
			defer s.Close()
			return get(s.URL)
		}, false},
		{"a 404 whose body is not the adapter's JSON", func(*testing.T) error {
			s := reply(404, `<html>not found</html>`)
			defer s.Close()
			return get(s.URL)
		}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			err := row.err(t)
			if err == nil {
				t.Fatal("the call succeeded; every row here is a failure")
			}
			if got := deviceSaysAbsent(err); got != row.absent {
				t.Fatalf("deviceSaysAbsent = %v, want %v (err: %v)", got, row.absent, err)
			}
		})
	}
}

// A successful get is not an error at all.
func TestAnAnsweredGetIsNotAnError(t *testing.T) {
	s := reply(200, `{"values":{".type":"interface","proto":"static"}}`)
	defer s.Close()
	if err := get(s.URL); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The provider matches the adapter's status-4 reply byte for byte, so the two
// must not drift. The adapter is in this repo; read its source and require the
// exact literal on the ClientError::Status(4) arm.
func TestTheAdapterStillSpellsNotFoundThisWay(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "crates", "ubus-http", "src", "http.rs"))
	if err != nil {
		t.Fatalf("reading the adapter source: %v", err)
	}
	text := string(src)
	arm := strings.Index(text, "Err(ClientError::Status(4))")
	if arm < 0 {
		t.Fatal("the adapter no longer has a ClientError::Status(4) arm")
	}
	window := text[arm:min(len(text), arm+200)]
	if !strings.Contains(window, `Response::error(404, "Not Found", "`+ubusNotFound+`")`) {
		t.Fatalf("the adapter's status-4 reply changed; update ubusNotFound to match:\n%s", window)
	}
}
