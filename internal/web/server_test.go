package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1:8484": true, "localhost:8484": true, "LOCALHOST": true, "[::1]:8484": true,
		"127.0.0.2": true, "localhost.:8484": true,
		"evil.example:8484": false, "192.168.1.10:8484": false, "": false,
	} {
		if got := loopbackHost(host); got != want {
			t.Errorf("loopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestAuthRejectsRebindingHost(t *testing.T) {
	s := &Server{}
	h := s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for host, want := range map[string]int{"127.0.0.1:8484": 200, "attacker.example:8484": 403} {
		req := httptest.NewRequest("GET", "/api/state", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %s: got %d, want %d", host, rec.Code, want)
		}
	}
}
