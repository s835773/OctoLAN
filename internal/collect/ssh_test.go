package collect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/vault"
)

type memKeys map[string]string

func (m memKeys) HostKey(ip string) string { return m[ip] }
func (m memKeys) RememberHostKey(ip, fp string) error {
	m[ip] = fp
	return nil
}

// fakeLinux is a tiny SSH server answering exec requests like a Linux box.
func fakeLinux(t *testing.T, password string) (netip.AddrPort, func()) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() == "ops" && string(p) == password {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							cmd := string(r.Payload[4:])
							r.Reply(true, nil)
							out := "sh: unknown command\n"
							switch {
							case cmd == "uname -a":
								out = "Linux nas01 6.1.0-18-amd64 #1 SMP x86_64 GNU/Linux\n"
							case strings.HasPrefix(cmd, "uname -sr;"):
								out = "Linux 6.1.0-18-amd64\n---\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n---\nup 3 weeks, 2 days\n---\n8\n---\n32000\n---\n71%\n"
							}
							ch.Write([]byte(out))
							ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	return ap, func() { ln.Close() }
}

func TestCollectSSHLinuxAndHostKeyPinning(t *testing.T) {
	ap, stop := fakeLinux(t, "pa55word")
	defer stop()
	// CollectSSH always dials port 22; point it at the test server.
	sshPortOverride = int(ap.Port())
	defer func() { sshPortOverride = 0 }()

	keys := memKeys{}
	dev := &model.Device{Ports: []model.Port{{Port: 22, Banner: "SSH-2.0-OpenSSH_9.2p1 Debian"}}}
	cred := vault.Cred{ID: "x", Type: vault.TypeSSH, Username: "ops", Password: "pa55word"}

	res, err := CollectSSH(context.Background(), ap.Addr(), dev, cred, keys)
	if err != nil {
		t.Fatal(err)
	}
	if res.Platform != PlatLinux || res.Linux == nil || res.Linux.Distro != "Debian GNU/Linux 12 (bookworm)" || res.Linux.CPUs != 8 || res.Linux.RootUse != 71 {
		t.Fatalf("got %+v / %+v", res, res.Linux)
	}
	if keys[ap.Addr().String()] == "" {
		t.Fatal("host key was not remembered")
	}

	// Wrong password is an auth error (counts toward lockout guard).
	bad := cred
	bad.Password = "nope"
	if _, err := CollectSSH(context.Background(), ap.Addr(), dev, bad, keys); !IsAuthError(err) {
		t.Fatalf("expected auth error, got %v", err)
	}

	// A different key on the same IP must stop the login before any
	// password is sent.
	keys[ap.Addr().String()] = "SHA256:somethingelse"
	if _, err := CollectSSH(context.Background(), ap.Addr(), dev, cred, keys); err == nil || !strings.Contains(err.Error(), "host key changed") {
		t.Fatalf("expected host key refusal, got %v", err)
	}
}
