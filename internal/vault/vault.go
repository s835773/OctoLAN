// Package vault is OctoLAN's encrypted credential container: one file per
// customer site holding the admin, SSH and SNMP credentials a customer has
// shared, plus the device config backups collected with them.
//
// File format (JSON envelope):
//
//	{"format":"octovault","version":1,
//	 "kdf":{"name":"argon2id","time":3,"memoryKiB":65536,"threads":4,"salt":"…"},
//	 "cipher":"xchacha20poly1305","nonce":"…","data":"…"}
//
// The key is derived from the passphrase with Argon2id; the payload is
// sealed with XChaCha20-Poly1305 using the canonical header as associated
// data, so tampering with the header or the data is detected. The
// passphrase is never stored.
package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// FileName is the vault's name inside a site folder.
const FileName = "credentials.octovault"

// MinPassphrase is the minimum passphrase length.
const MinPassphrase = 10

var (
	ErrLocked        = errors.New("vault is locked")
	ErrBadPassphrase = errors.New("wrong passphrase (or the vault file is damaged)")
	ErrExists        = errors.New("a vault already exists for this site")
	ErrNotFound      = errors.New("credential not found")
)

// Type of credential.
type Type string

const (
	TypeWindows Type = "windows" // WinRM (domain or local admin)
	TypeSSH     Type = "ssh"     // switches, firewalls, Linux
	TypeSNMP    Type = "snmp"    // v1/v2c community or v3 user
)

// Cred is one stored credential. Secret fields are only ever returned by
// Get/All for use by the scanner, never by View.
type Cred struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Type  Type     `json:"type"`
	Scope []string `json:"scope,omitempty"` // CIDRs/ranges/IPs; empty = the scan's targets
	Notes string   `json:"notes,omitempty"`

	// Windows / SSH
	Username string `json:"username,omitempty"`
	Domain   string `json:"domain,omitempty"` // Windows domain (blank = local account)
	Password string `json:"password,omitempty"`

	// SSH extras
	PrivateKey    string `json:"privateKey,omitempty"` // PEM
	KeyPassphrase string `json:"keyPassphrase,omitempty"`
	Enable        string `json:"enable,omitempty"` // Cisco-style enable secret

	// SNMP
	SNMPVersion string `json:"snmpVersion,omitempty"` // v2c | v3
	Community   string `json:"community,omitempty"`
	AuthProto   string `json:"authProto,omitempty"`
	AuthPass    string `json:"authPass,omitempty"`
	PrivProto   string `json:"privProto,omitempty"`
	PrivPass    string `json:"privPass,omitempty"`

	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// View is a credential without its secrets, safe to show in the UI.
type View struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        Type      `json:"type"`
	Scope       []string  `json:"scope,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	Username    string    `json:"username,omitempty"`
	Domain      string    `json:"domain,omitempty"`
	SNMPVersion string    `json:"snmpVersion,omitempty"`
	AuthProto   string    `json:"authProto,omitempty"`
	PrivProto   string    `json:"privProto,omitempty"`
	HasPassword bool      `json:"hasPassword"`
	HasKey      bool      `json:"hasKey"`
	HasEnable   bool      `json:"hasEnable"`
	Updated     time.Time `json:"updated"`
}

// ConfigBackup is a device configuration captured over SSH.
type ConfigBackup struct {
	DeviceID string    `json:"deviceId"`
	IP       string    `json:"ip"`
	Name     string    `json:"name"`
	Platform string    `json:"platform"`
	Command  string    `json:"command"`
	Text     string    `json:"text"`
	SHA256   string    `json:"sha256"`
	Captured time.Time `json:"captured"`
}

// ConfigView is a backup without its text.
type ConfigView struct {
	DeviceID string    `json:"deviceId"`
	IP       string    `json:"ip"`
	Name     string    `json:"name"`
	Platform string    `json:"platform"`
	Lines    int       `json:"lines"`
	SHA256   string    `json:"sha256"`
	Captured time.Time `json:"captured"`
	Versions int       `json:"versions"`
}

type payload struct {
	Site     string                    `json:"site"`
	Creds    []Cred                    `json:"creds"`
	Configs  map[string][]ConfigBackup `json:"configs,omitempty"`  // deviceID -> newest first
	HostKeys map[string]string         `json:"hostKeys,omitempty"` // ip -> SSH key fingerprint
	Created  time.Time                 `json:"created"`
}

type kdfParams struct {
	Name      string `json:"name"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memoryKiB"`
	Threads   uint8  `json:"threads"`
	Salt      string `json:"salt"`
}

type envelope struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	KDF     kdfParams `json:"kdf"`
	Cipher  string    `json:"cipher"`
	Nonce   string    `json:"nonce"`
	Data    string    `json:"data"`
}

// Defaults: ~0.3–1s on a laptop, 64 MiB to make GPU guessing expensive.
var defaultKDF = kdfParams{Name: "argon2id", Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

const maxConfigVersions = 5

// Vault is an open vault. It is safe for concurrent use.
type Vault struct {
	mu   sync.Mutex
	path string
	kdf  kdfParams
	key  []byte
	data *payload
}

// PathFor returns the vault path inside a site folder.
func PathFor(siteDir string) string { return filepath.Join(siteDir, FileName) }

// Exists reports whether a vault file is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func checkPassphrase(p string) error {
	if len([]rune(p)) < MinPassphrase {
		return fmt.Errorf("passphrase must be at least %d characters", MinPassphrase)
	}
	return nil
}

func deriveKey(pass string, k kdfParams) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(k.Salt)
	if err != nil || len(salt) < 16 {
		return nil, ErrBadPassphrase
	}
	if k.Name != "argon2id" || k.Time == 0 || k.Time > 20 || k.MemoryKiB < 8*1024 || k.MemoryKiB > 1<<21 || k.Threads == 0 {
		return nil, errors.New("unsupported or unsafe key-derivation parameters in vault file")
	}
	return argon2.IDKey([]byte(pass), salt, k.Time, k.MemoryKiB, k.Threads, chacha20poly1305.KeySize), nil
}

func newSalt() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// aad binds the header to the ciphertext.
func aad(version int, k kdfParams, cipher string) []byte {
	return []byte(fmt.Sprintf("octovault|%d|%s|%d|%d|%d|%s|%s", version, k.Name, k.Time, k.MemoryKiB, k.Threads, k.Salt, cipher))
}

// Create makes a new vault at path for site.
func Create(path, site, passphrase string) (*Vault, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	if Exists(path) {
		return nil, ErrExists
	}
	k := defaultKDF
	salt, err := newSalt()
	if err != nil {
		return nil, err
	}
	k.Salt = salt
	key, err := deriveKey(passphrase, k)
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, kdf: k, key: key, data: &payload{Site: site, Created: time.Now(),
		Configs: map[string][]ConfigBackup{}, HostKeys: map[string]string{}}}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := v.saveLocked(); err != nil {
		return nil, err
	}
	return v, nil
}

// Open decrypts the vault at path.
func Open(path, passphrase string) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Format != "octovault" {
		return nil, errors.New("not an OctoLAN vault file")
	}
	if env.Version != 1 || env.Cipher != "xchacha20poly1305" {
		return nil, fmt.Errorf("unsupported vault version %d / %s", env.Version, env.Cipher)
	}
	key, err := deriveKey(passphrase, env.KDF)
	if err != nil {
		return nil, err
	}
	nonce, err1 := base64.StdEncoding.DecodeString(env.Nonce)
	ct, err2 := base64.StdEncoding.DecodeString(env.Data)
	if err1 != nil || err2 != nil {
		return nil, ErrBadPassphrase
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrBadPassphrase
	}
	pt, err := aead.Open(nil, nonce, ct, aad(env.Version, env.KDF, env.Cipher))
	if err != nil {
		return nil, ErrBadPassphrase
	}
	defer wipe(pt)
	var p payload
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, ErrBadPassphrase
	}
	if p.Configs == nil {
		p.Configs = map[string][]ConfigBackup{}
	}
	if p.HostKeys == nil {
		p.HostKeys = map[string]string{}
	}
	return &Vault{path: path, kdf: env.KDF, key: key, data: &p}, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (v *Vault) saveLocked() error {
	if v.key == nil {
		return ErrLocked
	}
	pt, err := json.Marshal(v.data)
	if err != nil {
		return err
	}
	defer wipe(pt)
	aead, err := chacha20poly1305.NewX(v.key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	env := envelope{Format: "octovault", Version: 1, KDF: v.kdf, Cipher: "xchacha20poly1305",
		Nonce: base64.StdEncoding.EncodeToString(nonce)}
	env.Data = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, pt, aad(env.Version, env.KDF, env.Cipher)))
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

// Path is the vault file location.
func (v *Vault) Path() string { return v.path }

// Site is the customer/site the vault belongs to.
func (v *Vault) Site() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.data == nil {
		return ""
	}
	return v.data.Site
}

// Lock forgets the key and every decrypted secret.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key != nil {
		wipe(v.key)
	}
	v.key, v.data = nil, nil
}

// Unlocked reports whether secrets are available.
func (v *Vault) Unlocked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.key != nil
}

// ChangePassphrase re-encrypts the vault under a new passphrase and salt.
func (v *Vault) ChangePassphrase(newPass string) error {
	if err := checkPassphrase(newPass); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrLocked
	}
	k := defaultKDF
	salt, err := newSalt()
	if err != nil {
		return err
	}
	k.Salt = salt
	key, err := deriveKey(newPass, k)
	if err != nil {
		return err
	}
	old, oldKDF := v.key, v.kdf
	v.key, v.kdf = key, k
	if err := v.saveLocked(); err != nil {
		v.key, v.kdf = old, oldKDF
		return err
	}
	wipe(old)
	return nil
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Validate checks a credential before saving.
func Validate(c *Cred) error {
	c.Name = strings.TrimSpace(c.Name)
	c.Username = strings.TrimSpace(c.Username)
	c.Domain = strings.TrimSpace(c.Domain)
	switch c.Type {
	case TypeWindows:
		if c.Username == "" {
			return errors.New("Windows credentials need a username")
		}
		if i := strings.IndexByte(c.Username, '\\'); i > 0 && c.Domain == "" {
			c.Domain, c.Username = c.Username[:i], c.Username[i+1:]
		}
	case TypeSSH:
		if c.Username == "" {
			return errors.New("SSH credentials need a username")
		}
	case TypeSNMP:
		if c.SNMPVersion == "" {
			c.SNMPVersion = "v2c"
		}
		if c.SNMPVersion == "v3" && c.Username == "" {
			return errors.New("SNMPv3 credentials need a user name")
		}
	default:
		return fmt.Errorf("unknown credential type %q", c.Type)
	}
	if c.Name == "" {
		c.Name = string(c.Type) + " " + c.Username
		if c.Type == TypeSNMP && c.SNMPVersion != "v3" {
			c.Name = "SNMP community"
		}
	}
	var scope []string
	for _, s := range c.Scope {
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
			if p = strings.TrimSpace(p); p != "" {
				scope = append(scope, p)
			}
		}
	}
	c.Scope = scope
	return nil
}

// Put adds or updates a credential. On update, empty secret fields keep
// their stored values (the UI never receives secrets to send back).
func (v *Vault) Put(c Cred) (View, error) {
	if err := Validate(&c); err != nil {
		return View{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return View{}, ErrLocked
	}
	now := time.Now()
	if c.ID != "" {
		for i, old := range v.data.Creds {
			if old.ID != c.ID {
				continue
			}
			keep := func(newV *string, oldV string) {
				if *newV == "" {
					*newV = oldV
				}
			}
			keep(&c.Password, old.Password)
			keep(&c.PrivateKey, old.PrivateKey)
			keep(&c.KeyPassphrase, old.KeyPassphrase)
			keep(&c.Enable, old.Enable)
			keep(&c.Community, old.Community)
			keep(&c.AuthPass, old.AuthPass)
			keep(&c.PrivPass, old.PrivPass)
			c.Created, c.Updated = old.Created, now
			v.data.Creds[i] = c
			return c.View(), v.saveLocked()
		}
		return View{}, ErrNotFound
	}
	c.ID, c.Created, c.Updated = newID(), now, now
	v.data.Creds = append(v.data.Creds, c)
	return c.View(), v.saveLocked()
}

// Delete removes a credential.
func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrLocked
	}
	for i, c := range v.data.Creds {
		if c.ID == id {
			v.data.Creds = append(v.data.Creds[:i], v.data.Creds[i+1:]...)
			return v.saveLocked()
		}
	}
	return ErrNotFound
}

// Get returns one credential with secrets (for the scanner).
func (v *Vault) Get(id string) (Cred, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return Cred{}, ErrLocked
	}
	for _, c := range v.data.Creds {
		if c.ID == id {
			return c, nil
		}
	}
	return Cred{}, ErrNotFound
}

// All returns every credential with secrets (for the scanner).
func (v *Vault) All() ([]Cred, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return nil, ErrLocked
	}
	return append([]Cred(nil), v.data.Creds...), nil
}

// Views lists credentials without secrets.
func (v *Vault) Views() []View {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.data == nil {
		return nil
	}
	out := make([]View, 0, len(v.data.Creds))
	for _, c := range v.data.Creds {
		out = append(out, c.View())
	}
	return out
}

// View strips secrets.
func (c Cred) View() View {
	return View{ID: c.ID, Name: c.Name, Type: c.Type, Scope: c.Scope, Notes: c.Notes, Username: c.Username,
		Domain: c.Domain, SNMPVersion: c.SNMPVersion, AuthProto: c.AuthProto, PrivProto: c.PrivProto,
		HasPassword: c.Password != "" || c.Community != "" || c.AuthPass != "", HasKey: c.PrivateKey != "",
		HasEnable: c.Enable != "", Updated: c.Updated}
}

// ---- SSH host keys (trust on first use) ----

// HostKey returns the remembered fingerprint for ip.
func (v *Vault) HostKey(ip string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.data == nil {
		return ""
	}
	return v.data.HostKeys[ip]
}

// RememberHostKey stores the fingerprint seen for ip.
func (v *Vault) RememberHostKey(ip, fp string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrLocked
	}
	v.data.HostKeys[ip] = fp
	return v.saveLocked()
}

// ForgetHostKey clears a remembered key (after the tech confirms a device
// was legitimately replaced).
func (v *Vault) ForgetHostKey(ip string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrLocked
	}
	delete(v.data.HostKeys, ip)
	return v.saveLocked()
}

// ---- config backups ----

// AddConfig stores a config backup, keeping the newest few versions. It
// returns false if the config is unchanged from the latest version.
func (v *Vault) AddConfig(b ConfigBackup) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return false, ErrLocked
	}
	list := v.data.Configs[b.DeviceID]
	if len(list) > 0 && list[0].SHA256 == b.SHA256 {
		list[0].Captured = b.Captured
		return false, v.saveLocked()
	}
	list = append([]ConfigBackup{b}, list...)
	if len(list) > maxConfigVersions {
		list = list[:maxConfigVersions]
	}
	v.data.Configs[b.DeviceID] = list
	return true, v.saveLocked()
}

// Config returns the newest backup for a device.
func (v *Vault) Config(deviceID string) (ConfigBackup, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.data == nil || len(v.data.Configs[deviceID]) == 0 {
		return ConfigBackup{}, false
	}
	return v.data.Configs[deviceID][0], true
}

// ConfigViews lists backups without their text.
func (v *Vault) ConfigViews() []ConfigView {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.data == nil {
		return nil
	}
	var out []ConfigView
	for _, list := range v.data.Configs {
		if len(list) == 0 {
			continue
		}
		b := list[0]
		out = append(out, ConfigView{DeviceID: b.DeviceID, IP: b.IP, Name: b.Name, Platform: b.Platform,
			Lines: strings.Count(b.Text, "\n") + 1, SHA256: b.SHA256, Captured: b.Captured, Versions: len(list)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
