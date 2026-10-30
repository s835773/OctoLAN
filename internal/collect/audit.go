package collect

import (
	"regexp"
	"strings"
	"sync"
)

type syncMutex = sync.Mutex

// Config issue keys (turned into findings by the assessment).
const (
	IssueEnablePassword   = "enable-password-plaintext"
	IssueNoPwEncryption   = "no-service-password-encryption"
	IssueTelnetVTY        = "vty-telnet"
	IssueHTTPServer       = "http-server"
	IssueSNMPWrite        = "snmp-rw-community"
	IssueNoSyslog         = "no-remote-syslog"
	IssueNoNTP            = "no-ntp"
	IssueWeakLocalUser    = "local-user-weak-hash"
	IssueNoAAA            = "no-aaa"
	IssueSmartInstall     = "smart-install"
	IssueFortiHTTPAdmin   = "forti-http-admin"
	IssueMikroTikServices = "routeros-insecure-services"
)

var (
	reEnablePw   = regexp.MustCompile(`(?m)^enable password `)
	reVTYTelnet  = regexp.MustCompile(`(?m)^\s*transport input (telnet|all|.*telnet)`)
	reHTTPServer = regexp.MustCompile(`(?m)^ip http server\s*$`)
	reSNMPRW     = regexp.MustCompile(`(?m)^snmp-server community \S+ (view \S+ )?RW`)
	reSyslog     = regexp.MustCompile(`(?m)^logging (host )?\d+\.\d+\.\d+\.\d+|^logging host|^logging server`)
	reNTP        = regexp.MustCompile(`(?m)^ntp server|^ntp peer|^sntp server|^timesync`)
	reUserWeak   = regexp.MustCompile(`(?m)^username \S+ (privilege \d+ )?password (0|7) `)
	reAAA        = regexp.MustCompile(`(?m)^aaa new-model`)
	reVStack     = regexp.MustCompile(`(?m)^no vstack`)
)

// AuditConfig checks a config backup for common hardening gaps. Only
// Cisco-style (IOS/NX-OS/EOS/Aruba) and a few FortiOS/RouterOS rules
// apply; other platforms return no issues rather than false alarms.
func AuditConfig(plat Platform, cfg string) []string {
	var out []string
	add := func(k string) { out = append(out, k) }
	switch plat {
	case PlatCiscoIOS, PlatArista, PlatNXOS, PlatArubaCX, PlatProCurve:
		if reEnablePw.MatchString(cfg) {
			add(IssueEnablePassword)
		}
		if plat == PlatCiscoIOS && !strings.Contains(cfg, "service password-encryption") {
			add(IssueNoPwEncryption)
		}
		if reVTYTelnet.MatchString(cfg) {
			add(IssueTelnetVTY)
		}
		if reHTTPServer.MatchString(cfg) {
			add(IssueHTTPServer)
		}
		if reSNMPRW.MatchString(cfg) {
			add(IssueSNMPWrite)
		}
		if !reSyslog.MatchString(cfg) {
			add(IssueNoSyslog)
		}
		if !reNTP.MatchString(cfg) {
			add(IssueNoNTP)
		}
		if reUserWeak.MatchString(cfg) {
			add(IssueWeakLocalUser)
		}
		if plat == PlatCiscoIOS && !reAAA.MatchString(cfg) {
			add(IssueNoAAA)
		}
		if plat == PlatCiscoIOS && !reVStack.MatchString(cfg) && strings.Contains(cfg, "vstack") {
			add(IssueSmartInstall)
		}
	case PlatFortiOS:
		if strings.Contains(cfg, "set admin-http") && strings.Contains(cfg, "set allowaccess") && strings.Contains(cfg, " http ") {
			add(IssueFortiHTTPAdmin)
		}
		if !strings.Contains(cfg, "config log syslogd") {
			add(IssueNoSyslog)
		}
	case PlatMikroTik:
		for _, svc := range []string{"telnet", "ftp", "www", "api"} {
			if strings.Contains(cfg, "set "+svc+" disabled=no") {
				add(IssueMikroTikServices)
				break
			}
		}
	}
	return out
}
