package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/s835773/OctoLAN/internal/vault"
)

// Unlock throttling: failed attempts add a growing delay.
var (
	unlockMu    sync.Mutex
	unlockFails int
)

func (s *Server) vaultRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/vault", s.vaultStatus)
	mux.HandleFunc("POST /api/vault/create", s.vaultCreate)
	mux.HandleFunc("POST /api/vault/unlock", s.vaultUnlock)
	mux.HandleFunc("POST /api/vault/lock", s.vaultLock)
	mux.HandleFunc("POST /api/vault/passphrase", s.vaultPassphrase)
	mux.HandleFunc("POST /api/vault/creds", s.vaultPut)
	mux.HandleFunc("DELETE /api/vault/creds/{id}", s.vaultDelete)
	mux.HandleFunc("POST /api/vault/test", s.vaultTest)
	mux.HandleFunc("POST /api/vault/hostkey/forget", s.vaultForgetHostKey)
	mux.HandleFunc("GET /api/vault/config/{device}", s.vaultConfig)
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func (s *Server) vaultStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.E.VaultStatus())
}

type passBody struct {
	Passphrase string `json:"passphrase"`
	New        string `json:"newPassphrase"`
}

func readPass(w http.ResponseWriter, r *http.Request) (passBody, bool) {
	var b passBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&b); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return b, false
	}
	return b, true
}

func (s *Server) vaultCreate(w http.ResponseWriter, r *http.Request) {
	b, ok := readPass(w, r)
	if !ok {
		return
	}
	if err := s.E.VaultCreate(b.Passphrase); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, s.E.VaultStatus())
}

func (s *Server) vaultUnlock(w http.ResponseWriter, r *http.Request) {
	b, ok := readPass(w, r)
	if !ok {
		return
	}
	unlockMu.Lock()
	defer unlockMu.Unlock()
	if unlockFails > 0 {
		time.Sleep(time.Duration(min(unlockFails, 10)) * time.Second)
	}
	if err := s.E.VaultUnlock(b.Passphrase); err != nil {
		if errors.Is(err, vault.ErrBadPassphrase) {
			unlockFails++
		}
		httpErr(w, http.StatusForbidden, err)
		return
	}
	unlockFails = 0
	writeJSON(w, s.E.VaultStatus())
}

func (s *Server) vaultLock(w http.ResponseWriter, r *http.Request) {
	s.E.VaultLock()
	writeJSON(w, s.E.VaultStatus())
}

func (s *Server) vaultPassphrase(w http.ResponseWriter, r *http.Request) {
	b, ok := readPass(w, r)
	if !ok {
		return
	}
	v := s.E.Vault()
	if v == nil {
		httpErr(w, http.StatusForbidden, vault.ErrLocked)
		return
	}
	// Re-verify the current passphrase before changing it.
	if _, err := vault.Open(v.Path(), b.Passphrase); err != nil {
		httpErr(w, http.StatusForbidden, errors.New("current passphrase is incorrect"))
		return
	}
	if err := v.ChangePassphrase(b.New); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) vaultPut(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	v := s.E.Vault()
	if v == nil {
		httpErr(w, http.StatusForbidden, vault.ErrLocked)
		return
	}
	var c vault.Cred
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<17)).Decode(&c); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	view, err := v.Put(c)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	s.E.St.Logf("vault", "Saved credential %q (%s)", view.Name, view.Type)
	writeJSON(w, view)
}

func (s *Server) vaultDelete(w http.ResponseWriter, r *http.Request) {
	v := s.E.Vault()
	if v == nil {
		httpErr(w, http.StatusForbidden, vault.ErrLocked)
		return
	}
	if err := v.Delete(r.PathValue("id")); err != nil {
		httpErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) vaultTest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&b); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	msg, err := s.E.TestCredential(r.Context(), b.ID, b.IP)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": msg})
}

func (s *Server) vaultForgetHostKey(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IP string `json:"ip"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&b)
	v := s.E.Vault()
	if v == nil {
		httpErr(w, http.StatusForbidden, vault.ErrLocked)
		return
	}
	if err := v.ForgetHostKey(strings.TrimSpace(b.IP)); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// vaultConfig downloads a device's latest config backup (vault must be
// unlocked; configs contain secrets).
func (s *Server) vaultConfig(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	v := s.E.Vault()
	if v == nil {
		httpErr(w, http.StatusForbidden, vault.ErrLocked)
		return
	}
	b, ok := v.Config(r.PathValue("device"))
	if !ok {
		httpErr(w, http.StatusNotFound, errors.New("no config backup for this device"))
		return
	}
	name := strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`/\:*?"<>| `, r) {
			return '_'
		}
		return r
	}, b.Name)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`-`+b.Captured.Format("2006-01-02")+`.cfg"`)
	_, _ = w.Write([]byte(b.Text))
}
