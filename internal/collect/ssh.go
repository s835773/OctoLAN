package collect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/vault"
)

// ErrHostKeyChanged means the device presented a different SSH key than
// the one remembered in the vault: possible interception, so no password
// is sent.
var ErrHostKeyChanged = errors.New("SSH host key changed since the last visit (possible interception); credentials were not sent")

// sshPortOverride lets tests point the collector at a local server.
var sshPortOverride int

// Platform is the detected device family.
type Platform string

const (
	PlatCiscoIOS Platform = "cisco-ios"
	PlatNXOS     Platform = "cisco-nxos"
	PlatArista   Platform = "arista-eos"
	PlatJunos    Platform = "junos"
	PlatFortiOS  Platform = "fortios"
	PlatMikroTik Platform = "routeros"
	PlatProCurve Platform = "aruba-procurve"
	PlatArubaCX  Platform = "aruba-cx"
	PlatLinux    Platform = "linux"
	PlatUnknown  Platform = ""
)

// SSHResult is everything gathered from one host.
type SSHResult struct {
	Platform   Platform
	Linux      *model.LinuxInfo
	NetOS      *model.NetOSInfo
	Config     string
	ConfigCmd  string
	HostKeyFP  string
	NewHostKey bool
}

// HostKeys lets the collector check and remember fingerprints.
type HostKeys interface {
	HostKey(ip string) string
	RememberHostKey(ip, fp string) error
}

// Fingerprint is the SHA-256 fingerprint of an SSH public key.
func Fingerprint(k ssh.PublicKey) string {
	sum := sha256.Sum256(k.Marshal())
	return "SHA256:" + hex.EncodeToString(sum[:])
}

func sshConfig(c vault.Cred, ip string, keys HostKeys, res *SSHResult) (*ssh.ClientConfig, error) {
	var auths []ssh.AuthMethod
	if c.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if c.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(c.PrivateKey), []byte(c.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(c.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if c.Password != "" {
		pw := c.Password
		auths = append(auths, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	if len(auths) == 0 {
		return nil, errors.New("credential has no password or key")
	}
	return &ssh.ClientConfig{
		User: c.Username,
		Auth: auths,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := Fingerprint(key)
			res.HostKeyFP = fp
			known := ""
			if keys != nil {
				known = keys.HostKey(ip)
			}
			if known != "" && known != fp {
				return ErrHostKeyChanged
			}
			res.NewHostKey = known == ""
			return nil
		},
		Timeout: 12 * time.Second,
		// Older switches only offer legacy algorithms; allow them for this
		// read-only session.
		Config: ssh.Config{KeyExchanges: append(ssh.SupportedAlgorithms().KeyExchanges, ssh.InsecureAlgorithms().KeyExchanges...),
			Ciphers: append(ssh.SupportedAlgorithms().Ciphers, ssh.InsecureAlgorithms().Ciphers...)},
		HostKeyAlgorithms: append(ssh.SupportedAlgorithms().HostKeys, ssh.InsecureAlgorithms().HostKeys...),
	}, nil
}

// GuessPlatform uses discovery evidence to pick the command set.
func GuessPlatform(d *model.Device) Platform {
	text := strings.ToLower(d.Vendor + " " + d.OS.Family + " " + d.OS.Name + " " + d.Model + " " + d.Firmware)
	if d.SNMP != nil {
		text += " " + strings.ToLower(d.SNMP.SysDescr)
	}
	for _, p := range d.Ports {
		if p.Port == 22 {
			text += " " + strings.ToLower(p.Banner)
		}
	}
	switch {
	case strings.Contains(text, "nx-os"):
		return PlatNXOS
	case strings.Contains(text, "cisco"):
		return PlatCiscoIOS
	case strings.Contains(text, "arista"):
		return PlatArista
	case strings.Contains(text, "junos") || strings.Contains(text, "juniper"):
		return PlatJunos
	case strings.Contains(text, "fortigate") || strings.Contains(text, "fortios") || strings.Contains(text, "fortinet"):
		return PlatFortiOS
	case strings.Contains(text, "routeros") || strings.Contains(text, "mikrotik") || strings.Contains(text, "rosssh"):
		return PlatMikroTik
	case strings.Contains(text, "aos-cx") || strings.Contains(text, "arubaos-cx"):
		return PlatArubaCX
	case strings.Contains(text, "procurve") || strings.Contains(text, "arubaos-switch") || strings.Contains(text, "hewlett") && d.Type == model.TypeSwitch:
		return PlatProCurve
	case strings.Contains(text, "linux") || strings.Contains(text, "openssh") || strings.Contains(text, "ubuntu") || strings.Contains(text, "debian") || strings.Contains(text, "synology"):
		return PlatLinux
	}
	switch d.Type {
	case model.TypeSwitch, model.TypeRouter:
		return PlatCiscoIOS // most common; detection below corrects it
	}
	return PlatUnknown
}

// CollectSSH logs in, identifies the platform, gathers facts and (for
// network devices) backs up the configuration. Only read-only commands
// are run.
func CollectSSH(ctx context.Context, ip netip.Addr, d *model.Device, c vault.Cred, keys HostKeys) (*SSHResult, error) {
	res := &SSHResult{}
	cfg, err := sshConfig(c, ip.String(), keys, res)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 12 * time.Second}
	port := uint16(22)
	if sshPortOverride != 0 {
		port = uint16(sshPortOverride)
	}
	conn, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, ip.String(), cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()
	if res.NewHostKey && keys != nil {
		_ = keys.RememberHostKey(ip.String(), res.HostKeyFP)
	}
	go func() {
		<-ctx.Done()
		client.Close()
	}()

	plat := GuessPlatform(d)
	if plat == PlatUnknown || plat == PlatLinux {
		out, err := execCmd(client, "uname -a")
		lo := strings.ToLower(out)
		if err == nil && (strings.Contains(lo, "linux") || strings.Contains(lo, "bsd") || strings.Contains(lo, "darwin")) {
			plat = PlatLinux
		} else if plat == PlatLinux {
			plat = PlatUnknown
		}
	}
	if plat == PlatUnknown {
		// Ask the device who it is.
		if out, err := execCmd(client, "show version"); err == nil {
			plat = platformFromVersion(out)
		}
	}
	res.Platform = plat

	switch plat {
	case PlatLinux:
		res.Linux = collectLinux(client)
	case PlatCiscoIOS, PlatNXOS, PlatArista, PlatArubaCX:
		ver := runNet(client, plat, c, "show version")
		if p := platformFromVersion(ver); p != PlatUnknown {
			plat, res.Platform = p, p
		}
		res.NetOS = parseShowVersion(plat, ver)
		res.ConfigCmd = "show running-config"
		res.Config = cleanConfig(runNet(client, plat, c, res.ConfigCmd))
	case PlatProCurve:
		res.NetOS = parseShowVersion(plat, runNet(client, plat, c, "show system"))
		res.ConfigCmd = "show running-config"
		res.Config = cleanConfig(runNet(client, plat, c, res.ConfigCmd))
	case PlatJunos:
		out, _ := execCmd(client, "show version | no-more")
		res.NetOS = parseShowVersion(plat, out)
		res.ConfigCmd = "show configuration | display set | no-more"
		res.Config, _ = execCmd(client, res.ConfigCmd)
	case PlatFortiOS:
		out, _ := execCmd(client, "get system status")
		res.NetOS = parseFortiStatus(out)
		res.ConfigCmd = "show"
		res.Config, _ = execCmd(client, res.ConfigCmd)
	case PlatMikroTik:
		out, _ := execCmd(client, "/system resource print")
		res.NetOS = parseMikroTik(out)
		res.ConfigCmd = "/export hide-sensitive"
		res.Config, _ = execCmd(client, res.ConfigCmd)
	default:
		return res, errors.New("logged in, but the device type wasn't recognized; no data collected")
	}
	if res.Config != "" && !looksLikeConfig(res.Config) {
		res.Config = "" // error text, not a config (e.g. insufficient privilege)
	}
	return res, nil
}

func execCmd(client *ssh.Client, cmd string) (string, error) {
	s, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	// Stdout and stderr are copied by separate goroutines: share a locked buffer.
	var out safeBuf
	s.Stdout = &out
	s.Stderr = &out
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case err = <-done:
	case <-time.After(60 * time.Second):
		err = errors.New("command timed out")
	}
	return out.String(), err
}

var promptRe = regexp.MustCompile(`(?m)[\w.\-()/:@]+(\(config[^)]*\))?[#>]\s*$`)

// runNet drives an interactive shell, which many switches require: it
// disables paging, optionally enters enable mode, runs one command and
// returns its output.
func runNet(client *ssh.Client, plat Platform, c vault.Cred, cmd string) string {
	s, err := client.NewSession()
	if err != nil {
		return ""
	}
	defer s.Close()
	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := s.RequestPty("vt100", 400, 512, modes); err != nil {
		return ""
	}
	in, err := s.StdinPipe()
	if err != nil {
		return ""
	}
	var buf safeBuf
	s.Stdout, s.Stderr = &buf, &buf
	if err := s.Shell(); err != nil {
		return ""
	}
	wait := func(d time.Duration) string {
		// Wait for output to go quiet (or a prompt) up to d.
		end := time.Now().Add(d)
		last := -1
		for time.Now().Before(end) {
			time.Sleep(300 * time.Millisecond)
			n := buf.Len()
			if n == last && n > 0 && promptRe.MatchString(tail(buf.String(), 200)) {
				break
			}
			// ProCurve "Press any key to continue"
			if strings.Contains(tail(buf.String(), 200), "any key to continue") {
				io.WriteString(in, "\n")
			}
			last = n
		}
		return buf.String()
	}
	wait(4 * time.Second)
	switch plat {
	case PlatProCurve:
		io.WriteString(in, "no page\n")
	case PlatArubaCX:
		io.WriteString(in, "no page\n")
	case PlatNXOS, PlatCiscoIOS, PlatArista:
		io.WriteString(in, "terminal length 0\n")
	}
	wait(3 * time.Second)
	if c.Enable != "" && strings.HasSuffix(strings.TrimSpace(tail(buf.String(), 80)), ">") {
		io.WriteString(in, "enable\n")
		time.Sleep(700 * time.Millisecond)
		io.WriteString(in, c.Enable+"\n")
		wait(3 * time.Second)
	}
	start := buf.Len()
	io.WriteString(in, cmd+"\n")
	out := wait(45 * time.Second)
	io.WriteString(in, "exit\n")
	if start > len(out) {
		return ""
	}
	return stripCmdEcho(out[start:], cmd)
}

type safeBuf struct {
	mu  syncMutex
	buf bytes.Buffer
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() > 8<<20 {
		return len(p), nil
	}
	return b.buf.Write(p)
}
func (b *safeBuf) Len() int { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.Len() }
func (b *safeBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func stripCmdEcho(out, cmd string) string {
	out = ansiRe.ReplaceAllString(strings.ReplaceAll(out, "\r", ""), "")
	lines := strings.Split(out, "\n")
	if len(lines) > 0 && strings.Contains(lines[0], cmd) {
		lines = lines[1:]
	}
	// Drop the trailing prompt.
	for len(lines) > 0 && (strings.TrimSpace(lines[len(lines)-1]) == "" || promptRe.MatchString(lines[len(lines)-1])) {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

func cleanConfig(s string) string {
	s = strings.TrimSpace(s)
	// Cisco prefixes "Building configuration..." and "Current configuration : N bytes".
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "Building configuration") || strings.HasPrefix(l, "Current configuration") {
			continue
		}
		keep = append(keep, strings.TrimRight(l, " "))
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}

func looksLikeConfig(s string) bool {
	l := strings.ToLower(s)
	if strings.Contains(l, "% invalid") || strings.Contains(l, "privilege") && len(s) < 400 || strings.Contains(l, "unknown command") && len(s) < 400 {
		return false
	}
	return strings.Count(s, "\n") >= 5
}

func platformFromVersion(out string) Platform {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "nx-os"):
		return PlatNXOS
	case strings.Contains(l, "arista"):
		return PlatArista
	case strings.Contains(l, "cisco ios") || strings.Contains(l, "cisco internetwork"):
		return PlatCiscoIOS
	case strings.Contains(l, "junos"):
		return PlatJunos
	case strings.Contains(l, "arubaos-cx") || strings.Contains(l, "aos-cx"):
		return PlatArubaCX
	case strings.Contains(l, "procurve") || strings.Contains(l, "arubaos-switch"):
		return PlatProCurve
	}
	return PlatUnknown
}

var (
	reIOSVer    = regexp.MustCompile(`(?i)Version\s+([\w.()\-]+)`)
	reModel     = regexp.MustCompile(`(?im)^\s*(?:Model number|Model Number|cisco\s+(\S+).*processor|Hardware\s*:?\s*|Model)\s*:?\s*(\S+)?`)
	reSerial    = regexp.MustCompile(`(?im)(?:System serial number|Processor board ID|Serial number|Serial Number)\s*:?\s*(\S+)`)
	reUptime    = regexp.MustCompile(`(?im)uptime is (.+)$`)
	reCiscoHW   = regexp.MustCompile(`(?im)^cisco\s+(\S+)\s+\(`)
	reJunosModl = regexp.MustCompile(`(?im)^Model:\s*(\S+)`)
)

func parseShowVersion(plat Platform, out string) *model.NetOSInfo {
	n := &model.NetOSInfo{Platform: string(plat), Collected: time.Now()}
	if m := reIOSVer.FindStringSubmatch(out); m != nil {
		n.Version = strings.TrimSuffix(m[1], ",")
	}
	if m := reCiscoHW.FindStringSubmatch(out); m != nil {
		n.Model = m[1]
	} else if m := reJunosModl.FindStringSubmatch(out); m != nil {
		n.Model = m[1]
	} else if m := reModel.FindStringSubmatch(out); m != nil {
		n.Model = strings.TrimSpace(m[len(m)-1])
	}
	if m := reSerial.FindStringSubmatch(out); m != nil {
		n.Serial = m[1]
	}
	if m := reUptime.FindStringSubmatch(out); m != nil {
		n.Uptime = strings.TrimSpace(m[1])
	}
	return n
}

func kv(out, key string) string {
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parseFortiStatus(out string) *model.NetOSInfo {
	n := &model.NetOSInfo{Platform: string(PlatFortiOS), Collected: time.Now()}
	n.Version = kv(out, "Version")
	n.Serial = kv(out, "Serial-Number")
	if v := n.Version; v != "" {
		if f := strings.Fields(v); len(f) > 0 {
			n.Model = f[0]
		}
	}
	return n
}

func parseMikroTik(out string) *model.NetOSInfo {
	return &model.NetOSInfo{Platform: string(PlatMikroTik), Version: kv(out, "version"), Model: kv(out, "board-name"),
		Uptime: kv(out, "uptime"), Collected: time.Now()}
}

func collectLinux(client *ssh.Client) *model.LinuxInfo {
	out, _ := execCmd(client, `uname -sr; echo ---; cat /etc/os-release 2>/dev/null | grep ^PRETTY_NAME; echo ---; uptime -p 2>/dev/null || uptime; echo ---; nproc 2>/dev/null; echo ---; free -m 2>/dev/null | awk '/^Mem/{print $2}'; echo ---; df -P / | awk 'NR==2{print $5}'`)
	parts := strings.Split(out, "---")
	get := func(i int) string {
		if i < len(parts) {
			return strings.TrimSpace(parts[i])
		}
		return ""
	}
	li := &model.LinuxInfo{Kernel: get(0), Uptime: get(2), Collected: time.Now()}
	if pn := get(1); pn != "" {
		li.Distro = strings.Trim(strings.TrimPrefix(pn, "PRETTY_NAME="), `"`)
	}
	li.CPUs, _ = strconv.Atoi(get(3))
	li.MemMB, _ = strconv.Atoi(get(4))
	li.RootUse, _ = strconv.Atoi(strings.TrimSuffix(get(5), "%"))
	return li
}

// ConfigHash is the backup fingerprint.
func ConfigHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
