// Package collect runs credentialed checks with secrets from the vault:
// WinRM for Windows hosts and SSH for network gear and Linux. It decides
// which credential may be sent to which host, so admin secrets never leave
// their intended scope.
package collect

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/netutil"
	"github.com/s835773/OctoLAN/internal/vault"
)

// Scoper answers "may this credential be used on this IP?".
type Scoper struct {
	targets map[netip.Addr]bool
	mu      sync.Mutex
	cache   map[string]map[netip.Addr]bool
}

// NewScoper uses targets as the default scope for credentials that
// don't list their own.
func NewScoper(targets []netip.Addr) *Scoper {
	t := make(map[netip.Addr]bool, len(targets))
	for _, a := range targets {
		t[a] = true
	}
	return &Scoper{targets: t, cache: map[string]map[netip.Addr]bool{}}
}

// Allows reports whether c may be used against ip.
func (s *Scoper) Allows(c vault.Cred, ip netip.Addr) bool {
	if len(c.Scope) == 0 {
		return s.targets[ip]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	set, ok := s.cache[c.ID]
	if !ok {
		addrs, err := netutil.ParseTargets(c.Scope)
		set = map[netip.Addr]bool{}
		if err == nil {
			for _, a := range addrs {
				set[a] = true
			}
		}
		s.cache[c.ID] = set
	}
	return set[ip]
}

// WindowsCandidate reports whether d should get Windows credentials:
// Windows evidence plus WinRM listening.
func WindowsCandidate(d *model.Device) bool {
	if !hasPort(d, 5985) && !hasPort(d, 5986) {
		return false
	}
	return d.SMB != nil || strings.EqualFold(d.OS.Family, "Windows") || hasPort(d, 135) || hasPort(d, 445)
}

// SSHCandidate reports whether d should get SSH credentials.
func SSHCandidate(d *model.Device) bool { return hasPort(d, 22) }

// DomainMatches guards NTLM: a domain credential is only offered to hosts
// that belong to that domain (or whose domain is unknown but were
// explicitly scoped). This stops a rogue machine on the LAN from
// collecting a domain admin's NTLM response.
func DomainMatches(c vault.Cred, d *model.Device) bool {
	cd := strings.ToLower(strings.TrimSpace(c.Domain))
	if cd == "" || cd == "." {
		return true // local account
	}
	hd := strings.ToLower(d.Domain)
	if d.SMB != nil {
		if d.SMB.DNSDomain != "" {
			hd = strings.ToLower(d.SMB.DNSDomain)
		} else if d.SMB.NetBIOSDom != "" {
			hd = strings.ToLower(d.SMB.NetBIOSDom)
		}
	}
	if hd == "" {
		// Unknown domain: only allowed when the credential is explicitly
		// scoped (checked by the caller via Scope).
		return len(c.Scope) > 0
	}
	short := func(s string) string {
		if i := strings.IndexByte(s, '.'); i > 0 {
			return s[:i]
		}
		return s
	}
	return hd == cd || short(hd) == short(cd) || strings.HasSuffix(hd, "."+cd)
}

func hasPort(d *model.Device, p int) bool {
	for _, x := range d.Ports {
		if x.Port == p {
			return true
		}
	}
	return false
}

// IsAuthError reports whether err means "credentials rejected" (as
// opposed to a timeout or unsupported device), which counts toward the
// lockout guard.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, k := range []string{"401", "unauthorized", "unable to authenticate", "authentication failed",
		"access is denied", "access denied", "permission denied", "logon failure", "no supported methods remain"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// Guard pauses a credential after repeated rejections so a wrong or
// expired password can't lock the customer's account.
type Guard struct {
	mu       sync.Mutex
	fails    map[string]int
	disabled map[string]bool
	limit    int
}

// NewGuard allows `limit` consecutive auth failures per credential.
func NewGuard(limit int) *Guard {
	return &Guard{fails: map[string]int{}, disabled: map[string]bool{}, limit: limit}
}

// Allowed reports whether the credential may still be tried.
func (g *Guard) Allowed(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.disabled[id]
}

// Result records an attempt; it returns true when this failure disabled
// the credential.
func (g *Guard) Result(id string, err error) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err == nil {
		g.fails[id] = 0
		return false
	}
	if !IsAuthError(err) {
		return false
	}
	g.fails[id]++
	if g.fails[id] >= g.limit && !g.disabled[id] {
		g.disabled[id] = true
		return true
	}
	return false
}
