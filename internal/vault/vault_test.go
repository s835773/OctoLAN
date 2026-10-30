package vault

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	v, err := Create(path, "Acme", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	view, err := v.Put(Cred{Type: TypeWindows, Username: `ACME\admin`, Password: "S3cret!pass", Scope: []string{"10.0.0.0/24, 10.0.1.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if view.Domain != "ACME" || view.Username != "admin" || len(view.Scope) != 2 || !view.HasPassword {
		t.Fatalf("bad view %+v", view)
	}
	// Secrets must not be in the file in plaintext.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "S3cret") || strings.Contains(string(raw), "admin") {
		t.Fatal("plaintext leaked into vault file")
	}
	// Unix permission bits only; Windows protects the file with the user
	// profile's ACLs instead.
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("vault file mode %v", info.Mode().Perm())
	}

	v2, err := Open(path, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	all, _ := v2.All()
	if len(all) != 1 || all[0].Password != "S3cret!pass" {
		t.Fatalf("got %+v", all)
	}

	// Updating without secrets keeps the stored password.
	c := all[0]
	c.Password = ""
	c.Notes = "rotated in Q3"
	if _, err := v2.Put(c); err != nil {
		t.Fatal(err)
	}
	got, _ := v2.Get(c.ID)
	if got.Password != "S3cret!pass" || got.Notes != "rotated in Q3" {
		t.Fatalf("update lost secret: %+v", got)
	}

	if _, err := Open(path, "wrong passphrase!!"); err != ErrBadPassphrase {
		t.Fatalf("wrong passphrase: %v", err)
	}
	v2.Lock()
	if _, err := v2.All(); err != ErrLocked {
		t.Fatal("locked vault returned secrets")
	}
}

func TestTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	v, _ := Create(path, "Acme", "correct horse battery")
	_, _ = v.Put(Cred{Type: TypeSSH, Username: "netadmin", Password: "x"})
	raw, _ := os.ReadFile(path)
	var env envelope
	_ = json.Unmarshal(raw, &env)

	// Flip one ciphertext byte.
	ct, _ := base64.StdEncoding.DecodeString(env.Data)
	ct[len(ct)/2] ^= 1
	env.Data = base64.StdEncoding.EncodeToString(ct)
	b, _ := json.Marshal(env)
	_ = os.WriteFile(path, b, 0o600)
	if _, err := Open(path, "correct horse battery"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}

	// Weakening the KDF parameters in the header must also fail.
	_ = json.Unmarshal(raw, &env)
	env.KDF.Time = 1
	b, _ = json.Marshal(env)
	_ = os.WriteFile(path, b, 0o600)
	if _, err := Open(path, "correct horse battery"); err == nil {
		t.Fatal("tampered header accepted")
	}
}

func TestPassphraseRules(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(filepath.Join(dir, "a"), "x", "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	v, _ := Create(filepath.Join(dir, "b"), "x", "first passphrase")
	if err := v.ChangePassphrase("second passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(dir, "b"), "first passphrase"); err == nil {
		t.Fatal("old passphrase still works")
	}
	if _, err := Open(filepath.Join(dir, "b"), "second passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(filepath.Join(dir, "b"), "x", "another passphrase"); err != ErrExists {
		t.Fatal("overwrote an existing vault")
	}
}

func TestConfigVersions(t *testing.T) {
	v, _ := Create(filepath.Join(t.TempDir(), FileName), "x", "correct horse battery")
	for i, sha := range []string{"a", "a", "b", "c", "d", "e", "f"} {
		changed, _ := v.AddConfig(ConfigBackup{DeviceID: "sw1", SHA256: sha, Text: "hostname sw1\n"})
		if i == 1 && changed {
			t.Error("identical config counted as a change")
		}
	}
	views := v.ConfigViews()
	if len(views) != 1 || views[0].Versions != maxConfigVersions || views[0].SHA256 != "f" {
		t.Fatalf("got %+v", views)
	}
}
