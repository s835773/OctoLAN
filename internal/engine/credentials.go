package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/s835773/OctoLAN/internal/collect"
	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/vault"
)

// VaultIdleLock is how long an unlocked vault stays open without use.
const VaultIdleLock = 30 * time.Minute

// VaultStatus is what the dashboard shows (never secrets).
type VaultStatus struct {
	Site     string             `json:"site"`
	Path     string             `json:"path"`
	Exists   bool               `json:"exists"`
	Unlocked bool               `json:"unlocked"`
	Creds    []vault.View       `json:"creds"`
	Configs  []vault.ConfigView `json:"configs"`
	LocksAt  time.Time          `json:"locksAt,omitempty"`
}

type vaultState struct {
	mu      sync.Mutex
	v       *vault.Vault
	lastUse time.Time
	timer   *time.Timer
}

// VaultPath is the vault file for the current site.
func (e *Engine) VaultPath() string { return vault.PathFor(e.SessionDir()) }

func (e *Engine) requireSite() error {
	if strings.TrimSpace(e.St.Site()) == "" {
		return errors.New("set the customer / site name first: each customer gets its own vault")
	}
	return nil
}

// VaultStatus describes the current site's vault.
func (e *Engine) VaultStatus() VaultStatus {
	st := VaultStatus{Site: e.St.Site(), Path: e.VaultPath()}
	st.Exists = st.Site != "" && vault.Exists(st.Path)
	e.vs.mu.Lock()
	v := e.vs.v
	if v != nil {
		st.LocksAt = e.vs.lastUse.Add(VaultIdleLock)
	}
	e.vs.mu.Unlock()
	if v != nil && v.Unlocked() {
		st.Unlocked = true
		st.Creds = v.Views()
		st.Configs = v.ConfigViews()
	}
	if st.Creds == nil {
		st.Creds = []vault.View{}
	}
	return st
}

// VaultCreate makes a new vault for the current site and leaves it open.
func (e *Engine) VaultCreate(pass string) error {
	if err := e.requireSite(); err != nil {
		return err
	}
	v, err := vault.Create(e.VaultPath(), e.St.Site(), pass)
	if err != nil {
		return err
	}
	e.setVault(v)
	e.St.Logf("vault", "Created encrypted credential vault for %s", e.St.Site())
	return nil
}

// VaultUnlock opens the current site's vault.
func (e *Engine) VaultUnlock(pass string) error {
	if err := e.requireSite(); err != nil {
		return err
	}
	v, err := vault.Open(e.VaultPath(), pass)
	if err != nil {
		return err
	}
	e.setVault(v)
	e.St.Logf("vault", "Credential vault unlocked (auto-locks after %s idle)", VaultIdleLock)
	return nil
}

func (e *Engine) setVault(v *vault.Vault) {
	e.vs.mu.Lock()
	defer e.vs.mu.Unlock()
	if e.vs.v != nil && e.vs.v != v {
		e.vs.v.Lock()
	}
	e.vs.v = v
	e.vs.lastUse = time.Now()
	if e.vs.timer != nil {
		e.vs.timer.Stop()
	}
	e.vs.timer = time.AfterFunc(VaultIdleLock, e.idleCheck)
}

func (e *Engine) idleCheck() {
	e.vs.mu.Lock()
	idle := time.Since(e.vs.lastUse)
	if e.vs.v == nil {
		e.vs.mu.Unlock()
		return
	}
	if idle < VaultIdleLock || e.Running() {
		e.vs.timer = time.AfterFunc(VaultIdleLock-idle+time.Second, e.idleCheck)
		e.vs.mu.Unlock()
		return
	}
	e.vs.mu.Unlock()
	e.VaultLock()
	e.St.Logf("vault", "Credential vault locked after %s of inactivity", VaultIdleLock)
}

// VaultLock forgets the key and secrets.
func (e *Engine) VaultLock() {
	e.vs.mu.Lock()
	defer e.vs.mu.Unlock()
	if e.vs.v != nil {
		e.vs.v.Lock()
		e.vs.v = nil
	}
	if e.vs.timer != nil {
		e.vs.timer.Stop()
		e.vs.timer = nil
	}
}

// Vault returns the open vault (nil if locked) and marks it used.
func (e *Engine) Vault() *vault.Vault {
	e.vs.mu.Lock()
	defer e.vs.mu.Unlock()
	if e.vs.v == nil || !e.vs.v.Unlocked() {
		return nil
	}
	e.vs.lastUse = time.Now()
	return e.vs.v
}

// VaultUnlocked reports whether the vault is open.
func (e *Engine) VaultUnlocked() bool { return e.Vault() != nil }

// SetSite changes the site; an open vault for another site is locked so
// one customer's credentials can't be used at the next.
func (e *Engine) SetSite(name string) {
	name = strings.TrimSpace(name)
	if name == e.St.Site() {
		return
	}
	e.St.SetSite(name)
	e.VaultLock()
}

func (e *Engine) vaultCreds(cfg model.ScanConfig) []vault.Cred {
	if !cfg.UseVault {
		return nil
	}
	v := e.Vault()
	if v == nil {
		return nil
	}
	if !strings.EqualFold(v.Site(), e.St.Site()) {
		e.St.AddEvent(model.SevMedium, "vault", "Vault belongs to a different site; not used", "")
		return nil
	}
	creds, _ := v.All()
	return creds
}

func countHostCreds(cs []vault.Cred) int {
	n := 0
	for _, c := range cs {
		if c.Type == vault.TypeWindows || c.Type == vault.TypeSSH {
			n++
		}
	}
	return n
}

type credJob struct {
	dev  *model.Device
	ip   netip.Addr
	kind vault.Type
}

// credentialedChecks tries matching credentials on each eligible host.
// Rules: only in-scope hosts, only matching device types, domain creds
// only to same-domain hosts, one attempt per credential per host, and a
// credential is paused after repeated rejections (lockout guard).
func (e *Engine) credentialedChecks(ctx context.Context, t *tracker, targets []netip.Addr, creds []vault.Cred) {
	scope := collect.NewScoper(targets)
	guard := collect.NewGuard(3)
	v := e.Vault()

	var jobs []credJob
	for _, d := range e.St.Devices() {
		if d.IsSelf || !d.Alive || len(d.IPs) == 0 {
			continue
		}
		ip, err := netip.ParseAddr(d.IPs[0])
		if err != nil {
			continue
		}
		if collect.WindowsCandidate(d) {
			jobs = append(jobs, credJob{d, ip, vault.TypeWindows})
		}
		if collect.SSHCandidate(d) {
			jobs = append(jobs, credJob{d, ip, vault.TypeSSH})
		}
	}
	if len(jobs) == 0 {
		t.end("done", "no hosts with WinRM or SSH open")
		return
	}

	var mu sync.Mutex
	done, okWin, okSSH, configs := 0, 0, 0, 0
	work := make(chan credJob)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				res := e.tryHost(ctx, j, creds, scope, guard, v)
				mu.Lock()
				done++
				switch res {
				case "windows":
					okWin++
				case "ssh":
					okSSH++
				case "ssh+config":
					okSSH++
					configs++
				}
				t.progress(float64(done)/float64(len(jobs)), fmt.Sprintf("%d Windows and %d SSH hosts collected (%d/%d tried)", okWin, okSSH, done, len(jobs)))
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		work <- j
	}
	close(work)
	wg.Wait()
	t.end("done", fmt.Sprintf("%d Windows hosts, %d SSH hosts, %d configs backed up", okWin, okSSH, configs))
}

func (e *Engine) tryHost(ctx context.Context, j credJob, creds []vault.Cred, scope *collect.Scoper, guard *collect.Guard, v *vault.Vault) string {
	for _, c := range creds {
		if c.Type != j.kind || !scope.Allows(c, j.ip) || !guard.Allowed(c.ID) || ctx.Err() != nil {
			continue
		}
		if c.Type == vault.TypeWindows && !collect.DomainMatches(c, j.dev) {
			continue
		}
		var err error
		result := ""
		switch c.Type {
		case vault.TypeWindows:
			https := !hasPortNum(j.dev, 5985)
			var w *model.WindowsInfo
			w, err = collect.CollectWindows(ctx, j.ip, https, c)
			if err == nil {
				result = "windows"
				e.St.Update(j.dev.ID, func(d *model.Device) {
					d.Windows = w
					d.OS.Family, d.OS.Confidence = "Windows", 100
					d.OS.Name = strings.TrimPrefix(w.OS, "Microsoft ")
					if w.DisplayVersion != "" {
						d.OS.Name += " " + w.DisplayVersion
					}
					d.OS.Name += fmt.Sprintf(" (build %s.%d)", w.Build, w.UBR)
					d.OS.Evidence = appendUniq(d.OS.Evidence, "credentialed WinRM inventory")
					if d.Model == "" && w.Model != "" {
						d.Model = strings.TrimSpace(w.Manufacturer + " " + w.Model)
					}
					if d.Serial == "" {
						d.Serial = w.Serial
					}
				})
			}
		case vault.TypeSSH:
			var r *collect.SSHResult
			r, err = collect.CollectSSH(ctx, j.ip, j.dev, c, v)
			if errors.Is(err, collect.ErrHostKeyChanged) {
				e.St.AddEvent(model.SevHigh, "ssh", fmt.Sprintf("%s presented a different SSH host key than last time; credentials were not sent (possible interception, or the device was replaced)", j.ip), j.dev.ID)
			}
			if err == nil {
				result = "ssh"
				var info *model.ConfigInfo
				if r.Config != "" && v != nil {
					sum := collect.ConfigHash(r.Config)
					changed, _ := v.AddConfig(vault.ConfigBackup{DeviceID: j.dev.ID, IP: j.ip.String(), Name: deviceLabel(j.dev),
						Platform: string(r.Platform), Command: r.ConfigCmd, Text: r.Config, SHA256: sum, Captured: time.Now()})
					info = &model.ConfigInfo{Platform: string(r.Platform), Lines: strings.Count(r.Config, "\n") + 1, SHA256: sum,
						Captured: time.Now(), Changed: changed, Issues: collect.AuditConfig(r.Platform, r.Config)}
					result = "ssh+config"
				}
				e.St.Update(j.dev.ID, func(d *model.Device) {
					if r.Linux != nil {
						d.Linux = r.Linux
						if r.Linux.Distro != "" && d.OS.Confidence < 90 {
							d.OS.Family, d.OS.Name, d.OS.Confidence = "Linux", r.Linux.Distro, 90
						}
					}
					if r.NetOS != nil {
						d.NetOS = r.NetOS
						if d.Firmware == "" {
							d.Firmware = r.NetOS.Version
						}
						if d.Model == "" {
							d.Model = r.NetOS.Model
						}
						if d.Serial == "" {
							d.Serial = r.NetOS.Serial
						}
					}
					if info != nil {
						d.Config = info
					}
				})
			}
		}
		disabled := guard.Result(c.ID, err)
		e.St.Update(j.dev.ID, func(d *model.Device) {
			cr := model.CredResult{Method: methodName(c.Type), CredID: c.ID, CredName: c.Name, OK: err == nil, At: time.Now()}
			if err != nil {
				cr.Error = shortErr(err)
			}
			d.CredTries = append(d.CredTries, cr)
		})
		if disabled {
			e.St.AddEvent(model.SevHigh, "vault", fmt.Sprintf("Credential %q was rejected repeatedly; paused for the rest of this scan to avoid locking the account", c.Name), "")
		}
		if err == nil {
			return result
		}
		if collect.IsAuthError(err) || errors.Is(err, collect.ErrHostKeyChanged) {
			continue // try the next matching credential
		}
		// Connection-level failure: other credentials won't fare better.
		return ""
	}
	return ""
}

func methodName(t vault.Type) string {
	if t == vault.TypeWindows {
		return "winrm"
	}
	return string(t)
}

func shortErr(err error) string {
	s := err.Error()
	if collect.IsAuthError(err) {
		return "credentials rejected"
	}
	if len(s) > 140 {
		s = s[:140] + "…"
	}
	return s
}

func hasPortNum(d *model.Device, p int) bool {
	for _, x := range d.Ports {
		if x.Port == p {
			return true
		}
	}
	return false
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func deviceLabel(d *model.Device) string {
	if d.Hostname != "" {
		return d.Hostname
	}
	if len(d.IPs) > 0 {
		return d.IPs[0]
	}
	return d.ID
}

// TestCredential tries one credential against one host right now (from
// the dashboard's Test button). The usual scope/domain rules don't apply:
// the tech chose the host explicitly.
func (e *Engine) TestCredential(ctx context.Context, credID, ipStr string) (string, error) {
	v := e.Vault()
	if v == nil {
		return "", vault.ErrLocked
	}
	c, err := v.Get(credID)
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return "", fmt.Errorf("enter an IP address")
	}
	d := &model.Device{IPs: []string{ip.String()}}
	if id := e.St.FindByIP(ip.String()); id != "" {
		if dd := e.St.Get(id); dd != nil {
			d = dd
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	switch c.Type {
	case vault.TypeWindows:
		w, err := collect.CollectWindows(ctx, ip, !hasPortNum(d, 5985) && hasPortNum(d, 5986), c)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("WinRM OK: %s build %s, %d hotfixes, %d apps", w.OS, w.Build, w.HotfixCount, w.SoftwareCount), nil
	case vault.TypeSSH:
		r, err := collect.CollectSSH(ctx, ip, d, c, v)
		if err != nil {
			return "", err
		}
		msg := "SSH OK: " + string(r.Platform)
		if r.Linux != nil {
			msg += " · " + r.Linux.Distro
		}
		if r.NetOS != nil {
			msg += " · " + r.NetOS.Model + " " + r.NetOS.Version
		}
		if r.Config != "" {
			msg += fmt.Sprintf(" · config readable (%d lines)", strings.Count(r.Config, "\n")+1)
		}
		return msg, nil
	default:
		return "", errors.New("use a scan to test SNMP credentials")
	}
}
