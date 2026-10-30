package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/masterzen/winrm"

	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/vault"
)

// Two short read-only scripts (WinRM limits command length). Dates are
// emitted as ISO-8601 so both Windows PowerShell 5.1 and 7 agree.
const psSystem = `$ErrorActionPreference='SilentlyContinue';function d($x){if($x){([datetime]$x).ToUniversalTime().ToString('o')}}
$o=Get-CimInstance Win32_OperatingSystem;$c=Get-CimInstance Win32_ComputerSystem;$b=Get-CimInstance Win32_BIOS
$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$r=[ordered]@{os=$o.Caption;ver=$o.Version;build=$o.BuildNumber;ubr=$cv.UBR;disp=$cv.DisplayVersion;inst=d $o.InstallDate;boot=d $o.LastBootUpTime
mfr=$c.Manufacturer;model=$c.Model;serial=$b.SerialNumber;domain=$c.Domain;joined=[bool]$c.PartOfDomain;ram=[math]::Round($c.TotalPhysicalMemory/1GB,1)
cpu=(Get-CimInstance Win32_Processor|Select-Object -First 1).Name}
$h=@(Get-CimInstance Win32_QuickFixEngineering|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending)
$r.hfn=$h.Count;if($h.Count){$r.hf=d $h[0].InstalledOn;$r.hfid=$h[0].HotFixID}
$m=Get-MpComputerStatus;if($m){$r.rtp=[bool]$m.RealTimeProtectionEnabled;$r.av=[bool]$m.AntivirusEnabled;$r.sig=[int]$m.AntivirusSignatureAge}
$r.avp=@(Get-CimInstance -Namespace root/SecurityCenter2 AntiVirusProduct|ForEach-Object{$_.displayName})
$r.fw=@(Get-NetFirewallProfile|ForEach-Object{@{n=[string]$_.Name;e=[bool]$_.Enabled}})
$r.bl=@(Get-CimInstance -Namespace root/cimv2/security/microsoftvolumeencryption Win32_EncryptableVolume|ForEach-Object{@{d=$_.DriveLetter;p=[int]$_.ProtectionStatus}})
$r.disk=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|ForEach-Object{@{d=$_.DeviceID;s=[math]::Round($_.Size/1GB,1);f=[math]::Round($_.FreeSpace/1GB,1)}})
$r.reboot=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$s=Get-SmbServerConfiguration;if($s){$r.smb1=[bool]$s.EnableSMB1Protocol}
$t=Get-CimInstance -Namespace root/cimv2/TerminalServices Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'";if($t){$r.nla=[bool]$t.UserAuthenticationRequired}
$r.autologon=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').AutoAdminLogon -eq '1'
$r|ConvertTo-Json -Compress -Depth 4`

const psAccounts = `$ErrorActionPreference='SilentlyContinue';function d($x){if($x){([datetime]$x).ToUniversalTime().ToString('o')}}
$r=[ordered]@{}
$a=@(Get-LocalGroupMember -SID S-1-5-32-544|ForEach-Object{[string]$_.Name})
if(!$a.Count){$a=@(net localgroup administrators 2>$null|Select-Object -Skip 6|Where-Object{$_ -and $_ -notmatch 'command completed'})}
$r.admins=$a
$r.users=@(Get-LocalUser|ForEach-Object{@{n=$_.Name;e=[bool]$_.Enabled;p=d $_.PasswordLastSet}})
$k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$sw=@(Get-ItemProperty $k|Where-Object{$_.DisplayName -and !$_.SystemComponent}|Sort-Object DisplayName -Unique)
$r.swn=$sw.Count;$r.sw=@($sw|Select-Object -First 500|ForEach-Object{@{n=$_.DisplayName;v=[string]$_.DisplayVersion;p=[string]$_.Publisher}})
$r|ConvertTo-Json -Compress -Depth 4`

type psSys struct {
	OS     string   `json:"os"`
	Ver    string   `json:"ver"`
	Build  string   `json:"build"`
	UBR    int      `json:"ubr"`
	Disp   string   `json:"disp"`
	Inst   string   `json:"inst"`
	Boot   string   `json:"boot"`
	Mfr    string   `json:"mfr"`
	Model  string   `json:"model"`
	Serial string   `json:"serial"`
	Domain string   `json:"domain"`
	Joined bool     `json:"joined"`
	RAM    float64  `json:"ram"`
	CPU    string   `json:"cpu"`
	HFN    int      `json:"hfn"`
	HF     string   `json:"hf"`
	HFID   string   `json:"hfid"`
	RTP    *bool    `json:"rtp"`
	AV     *bool    `json:"av"`
	Sig    int      `json:"sig"`
	AVP    []string `json:"avp"`
	FW     []struct {
		N string `json:"n"`
		E bool   `json:"e"`
	} `json:"fw"`
	BL []struct {
		D string `json:"d"`
		P int    `json:"p"`
	} `json:"bl"`
	Disk []struct {
		D string  `json:"d"`
		S float64 `json:"s"`
		F float64 `json:"f"`
	} `json:"disk"`
	Reboot    bool  `json:"reboot"`
	SMB1      *bool `json:"smb1"`
	NLA       *bool `json:"nla"`
	AutoLogon bool  `json:"autologon"`
}

type psAcct struct {
	Admins []string `json:"admins"`
	Users  []struct {
		N string `json:"n"`
		E bool   `json:"e"`
		P string `json:"p"`
	} `json:"users"`
	SWN int `json:"swn"`
	SW  []struct {
		N string `json:"n"`
		V string `json:"v"`
		P string `json:"p"`
	} `json:"sw"`
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// ParseWindows turns the two script outputs into WindowsInfo.
func ParseWindows(sysJSON, acctJSON string) (*model.WindowsInfo, error) {
	var s psSys
	if err := json.Unmarshal([]byte(strings.TrimSpace(sysJSON)), &s); err != nil {
		return nil, fmt.Errorf("unexpected PowerShell output: %w", err)
	}
	w := &model.WindowsInfo{
		OS: strings.TrimSpace(s.OS), Version: s.Ver, Build: s.Build, UBR: s.UBR, DisplayVersion: s.Disp,
		InstallDate: parseTime(s.Inst), LastBoot: parseTime(s.Boot), Manufacturer: s.Mfr, Model: s.Model,
		Serial: strings.TrimSpace(s.Serial), CPU: strings.TrimSpace(s.CPU), RAMGB: s.RAM, Domain: s.Domain,
		DomainJoined: s.Joined, HotfixCount: s.HFN, LastHotfix: parseTime(s.HF), LastHotfixID: s.HFID,
		DefenderRTP: s.RTP, DefenderOn: s.AV, SigAgeDays: s.Sig, AVProducts: s.AVP,
		PendingReboot: s.Reboot, SMB1Enabled: s.SMB1, RDPNLA: s.NLA, AutoLogon: s.AutoLogon,
		Firewall: map[string]bool{}, Collected: time.Now(),
	}
	for _, f := range s.FW {
		w.Firewall[f.N] = f.E
	}
	for _, b := range s.BL {
		// ProtectionStatus: 0 off, 1 on, 2 unknown (locked)
		w.BitLocker = append(w.BitLocker, model.DriveCrypt{Drive: b.D, Protected: b.P == 1})
	}
	for _, d := range s.Disk {
		w.Disks = append(w.Disks, model.Disk{Drive: d.D, SizeGB: d.S, FreeGB: d.F})
	}
	if strings.TrimSpace(acctJSON) != "" {
		var a psAcct
		if err := json.Unmarshal([]byte(strings.TrimSpace(acctJSON)), &a); err == nil {
			for _, x := range a.Admins {
				if x = strings.TrimSpace(x); x != "" {
					w.Admins = append(w.Admins, x)
				}
			}
			for _, u := range a.Users {
				w.LocalUsers = append(w.LocalUsers, model.LocalUser{Name: u.N, Enabled: u.E, PwLast: parseTime(u.P)})
			}
			w.SoftwareCount = a.SWN
			for _, x := range a.SW {
				w.Software = append(w.Software, model.Software{Name: x.N, Version: x.V, Publisher: x.P})
			}
		}
	}
	return w, nil
}

// WindowsUser is how the account is presented to WinRM.
func WindowsUser(c vault.Cred) string {
	if c.Domain != "" && c.Domain != "." {
		return c.Domain + `\` + c.Username
	}
	return c.Username
}

// CollectWindows runs the read-only scripts over WinRM. HTTP (5985) is
// used with NTLM message encryption, which is what Windows requires by
// default; HTTPS (5986) is used when it's the only listener.
func CollectWindows(ctx context.Context, ip netip.Addr, useHTTPS bool, c vault.Cred) (*model.WindowsInfo, error) {
	port := 5985
	if useHTTPS {
		port = 5986
	}
	ep := winrm.NewEndpoint(ip.String(), port, useHTTPS, true, nil, nil, nil, 45*time.Second)
	params := *winrm.DefaultParameters
	if useHTTPS {
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	} else {
		enc, err := winrm.NewEncryption("ntlm")
		if err != nil {
			return nil, err
		}
		params.TransportDecorator = func() winrm.Transporter { return enc }
	}
	client, err := winrm.NewClientWithParameters(ep, WindowsUser(c), c.Password, &params)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, stderr, code, err := client.RunPSWithContextWithString(ctx, psSystem, "")
	if err != nil {
		return nil, err
	}
	if code != 0 && strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("PowerShell exited %d: %s", code, firstLine(stderr))
	}
	acct, _, _, aerr := client.RunPSWithContextWithString(ctx, psAccounts, "")
	if aerr != nil {
		acct = ""
	}
	w, err := ParseWindows(out, acct)
	if err != nil {
		return nil, err
	}
	if w.OS == "" {
		return nil, errors.New("WinRM session returned no system information")
	}
	return w, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
