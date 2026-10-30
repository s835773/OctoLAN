// Package model holds the data types shared across OctoLAN: devices,
// links, findings, flows and the live telemetry snapshots.
package model

import (
	"time"
)

// DeviceType is the classified role of a device on the network.
type DeviceType string

const (
	TypeUnknown     DeviceType = "unknown"
	TypeRouter      DeviceType = "router"
	TypeFirewall    DeviceType = "firewall"
	TypeSwitch      DeviceType = "switch"
	TypeAccessPoint DeviceType = "access-point"
	TypeServer      DeviceType = "server"
	TypeWorkstation DeviceType = "workstation"
	TypeHypervisor  DeviceType = "hypervisor"
	TypeNAS         DeviceType = "nas"
	TypePrinter     DeviceType = "printer"
	TypePhone       DeviceType = "voip-phone"
	TypeCamera      DeviceType = "camera"
	TypeMobile      DeviceType = "mobile"
	TypeMedia       DeviceType = "media"
	TypeIoT         DeviceType = "iot"
	TypeUPS         DeviceType = "ups"
)

// Source records which discovery method contributed a fact.
const (
	SrcARP       = "arp"
	SrcARPTable  = "arp-table"
	SrcICMP      = "icmp"
	SrcTCP       = "tcp"
	SrcSNMP      = "snmp"
	SrcLLDP      = "lldp"
	SrcCDP       = "cdp"
	SrcDHCP      = "dhcp"
	SrcMDNS      = "mdns"
	SrcSSDP      = "ssdp"
	SrcNetBIOS   = "netbios"
	SrcDNS       = "dns"
	SrcSMB       = "smb"
	SrcPassive   = "passive"
	SrcNetFlow   = "netflow"
	SrcLocalHost = "self"
)

// Device is one network endpoint. Devices are keyed by MAC when known,
// otherwise by IP.
type Device struct {
	ID        string     `json:"id"`
	IPs       []string   `json:"ips"`
	MAC       string     `json:"mac,omitempty"`
	Vendor    string     `json:"vendor,omitempty"`
	RandomMAC bool       `json:"randomMac,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	Names     []string   `json:"names,omitempty"` // every name seen (DNS, NetBIOS, mDNS, DHCP...)
	Domain    string     `json:"domain,omitempty"`
	Type      DeviceType `json:"type"`
	Model     string     `json:"model,omitempty"`
	Serial    string     `json:"serial,omitempty"`
	Firmware  string     `json:"firmware,omitempty"`
	Location  string     `json:"location,omitempty"`
	Contact   string     `json:"contact,omitempty"`

	OS       OSGuess   `json:"os"`
	RTTMicro int64     `json:"rttMicro,omitempty"` // best ICMP round trip in microseconds
	TTL      int       `json:"ttl,omitempty"`
	Ports    []Port    `json:"ports,omitempty"`
	Services []Service `json:"services,omitempty"` // mDNS / SSDP advertised services

	SNMP       *SNMPInfo   `json:"snmp,omitempty"`
	Interfaces []Interface `json:"interfaces,omitempty"`
	VLANs      []VLAN      `json:"vlans,omitempty"`
	Neighbors  []Neighbor  `json:"neighbors,omitempty"` // LLDP/CDP neighbours reported by this device
	FDB        []FDBEntry  `json:"fdb,omitempty"`       // switch MAC address table
	TLS        []TLSInfo   `json:"tls,omitempty"`
	SMB        *SMBInfo    `json:"smb,omitempty"`

	// Credentialed collection (from the vault).
	Windows   *WindowsInfo `json:"windows,omitempty"`
	Linux     *LinuxInfo   `json:"linux,omitempty"`
	NetOS     *NetOSInfo   `json:"netos,omitempty"`
	Config    *ConfigInfo  `json:"config,omitempty"`
	CredTries []CredResult `json:"credTries,omitempty"`

	Sources   []string  `json:"sources"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Alive     bool      `json:"alive"`
	IsSelf    bool      `json:"isSelf,omitempty"`
	IsGateway bool      `json:"isGateway,omitempty"`
	Notes     string    `json:"notes,omitempty"`
}

// OSGuess is the best operating system estimate with its evidence.
type OSGuess struct {
	Family     string   `json:"family,omitempty"` // Windows, Linux, macOS, iOS, Cisco IOS, ...
	Name       string   `json:"name,omitempty"`   // e.g. "Windows Server 2019 (build 17763)"
	Confidence int      `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	EOL        bool     `json:"eol,omitempty"`
	// Raw TCP/IP stack traits from SYN-ACK inspection.
	InitialTTL int  `json:"initialTtl,omitempty"`
	Window     int  `json:"window,omitempty"`
	DF         bool `json:"df,omitempty"`
	MSS        int  `json:"mss,omitempty"`
}

// Port is an open TCP port with any banner we grabbed.
type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// Service is an mDNS/SSDP advertisement.
type Service struct {
	Type   string `json:"type"`
	Name   string `json:"name,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// SNMPInfo is the system group plus how we reached the agent.
type SNMPInfo struct {
	Version     string `json:"version"`
	Community   string `json:"-"` // never serialized
	DefaultComm bool   `json:"defaultCommunity,omitempty"`
	SysDescr    string `json:"sysDescr,omitempty"`
	SysObjectID string `json:"sysObjectId,omitempty"`
	SysName     string `json:"sysName,omitempty"`
	SysUpTime   int64  `json:"sysUpTimeSec,omitempty"`
	SysServices int    `json:"sysServices,omitempty"`
}

// Interface is one interface row from IF-MIB.
type Interface struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Alias       string `json:"alias,omitempty"`
	Type        int    `json:"type,omitempty"`
	SpeedMbps   int64  `json:"speedMbps,omitempty"`
	MAC         string `json:"mac,omitempty"`
	AdminUp     bool   `json:"adminUp"`
	OperUp      bool   `json:"operUp"`
	InOctets    uint64 `json:"inOctets,omitempty"`
	OutOctets   uint64 `json:"outOctets,omitempty"`
	InErrors    uint64 `json:"inErrors,omitempty"`
	OutErrors   uint64 `json:"outErrors,omitempty"`
	PVID        int    `json:"pvid,omitempty"`
	TaggedVLANs []int  `json:"taggedVlans,omitempty"`
}

// VLAN seen on the wire or configured on a switch.
type VLAN struct {
	ID     int      `json:"id"`
	Name   string   `json:"name,omitempty"`
	Source string   `json:"source"`
	Tagged bool     `json:"tagged,omitempty"`
	Ports  []string `json:"ports,omitempty"`
}

// Neighbor is an LLDP/CDP adjacency.
type Neighbor struct {
	Protocol      string `json:"protocol"` // lldp | cdp
	LocalPort     string `json:"localPort,omitempty"`
	RemoteName    string `json:"remoteName,omitempty"`
	RemotePort    string `json:"remotePort,omitempty"`
	RemoteChassis string `json:"remoteChassis,omitempty"`
	RemoteIP      string `json:"remoteIp,omitempty"`
	RemoteDescr   string `json:"remoteDescr,omitempty"`
	RemoteCaps    string `json:"remoteCaps,omitempty"`
	NativeVLAN    int    `json:"nativeVlan,omitempty"`
}

// FDBEntry is one row of a switch forwarding table.
type FDBEntry struct {
	MAC  string `json:"mac"`
	Port string `json:"port"`
	VLAN int    `json:"vlan,omitempty"`
}

// TLSInfo describes a certificate presented on a port.
type TLSInfo struct {
	Port       int       `json:"port"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"notAfter"`
	SelfSigned bool      `json:"selfSigned"`
	Version    string    `json:"version,omitempty"`
}

// SMBInfo comes from an SMB negotiate + NTLM challenge.
type SMBInfo struct {
	SMB1         bool   `json:"smb1"`
	Dialect      string `json:"dialect,omitempty"`
	SigningReq   bool   `json:"signingRequired"`
	NetBIOSName  string `json:"netbiosName,omitempty"`
	NetBIOSDom   string `json:"netbiosDomain,omitempty"`
	DNSName      string `json:"dnsName,omitempty"`
	DNSDomain    string `json:"dnsDomain,omitempty"`
	OSBuild      string `json:"osBuild,omitempty"`
	OSMajorMinor string `json:"osVersion,omitempty"`
}

// CredResult records one credential attempt (never the secret).
type CredResult struct {
	Method   string    `json:"method"` // winrm | ssh | snmp
	CredID   string    `json:"credId"`
	CredName string    `json:"credName"`
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
}

// WindowsInfo comes from an authenticated WinRM session.
type WindowsInfo struct {
	OS             string          `json:"os"`
	Version        string          `json:"version"`
	Build          string          `json:"build"`
	UBR            int             `json:"ubr,omitempty"`
	DisplayVersion string          `json:"displayVersion,omitempty"`
	InstallDate    time.Time       `json:"installDate,omitempty"`
	LastBoot       time.Time       `json:"lastBoot,omitempty"`
	Manufacturer   string          `json:"manufacturer,omitempty"`
	Model          string          `json:"model,omitempty"`
	Serial         string          `json:"serial,omitempty"`
	CPU            string          `json:"cpu,omitempty"`
	RAMGB          float64         `json:"ramGb,omitempty"`
	Domain         string          `json:"domain,omitempty"`
	DomainJoined   bool            `json:"domainJoined"`
	HotfixCount    int             `json:"hotfixCount"`
	LastHotfix     time.Time       `json:"lastHotfix,omitempty"`
	LastHotfixID   string          `json:"lastHotfixId,omitempty"`
	DefenderRTP    *bool           `json:"defenderRealtime,omitempty"`
	DefenderOn     *bool           `json:"defenderEnabled,omitempty"`
	SigAgeDays     int             `json:"signatureAgeDays,omitempty"`
	AVProducts     []string        `json:"avProducts,omitempty"`
	Firewall       map[string]bool `json:"firewall,omitempty"`
	BitLocker      []DriveCrypt    `json:"bitlocker,omitempty"`
	Disks          []Disk          `json:"disks,omitempty"`
	PendingReboot  bool            `json:"pendingReboot"`
	SMB1Enabled    *bool           `json:"smb1Enabled,omitempty"`
	RDPNLA         *bool           `json:"rdpNla,omitempty"`
	AutoLogon      bool            `json:"autoLogon"`
	Admins         []string        `json:"admins,omitempty"`
	LocalUsers     []LocalUser     `json:"localUsers,omitempty"`
	SoftwareCount  int             `json:"softwareCount"`
	Software       []Software      `json:"software,omitempty"`
	Collected      time.Time       `json:"collected"`
}

// DriveCrypt is BitLocker status for one volume.
type DriveCrypt struct {
	Drive     string `json:"drive"`
	Protected bool   `json:"protected"`
}

// Disk is a fixed volume's capacity.
type Disk struct {
	Drive  string  `json:"drive"`
	SizeGB float64 `json:"sizeGb"`
	FreeGB float64 `json:"freeGb"`
}

// LocalUser is a local account.
type LocalUser struct {
	Name    string    `json:"name"`
	Enabled bool      `json:"enabled"`
	PwLast  time.Time `json:"passwordLastSet,omitempty"`
}

// Software is one installed application.
type Software struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}

// LinuxInfo comes from an SSH session on a Unix-like host.
type LinuxInfo struct {
	Distro    string    `json:"distro,omitempty"`
	Kernel    string    `json:"kernel,omitempty"`
	Uptime    string    `json:"uptime,omitempty"`
	CPUs      int       `json:"cpus,omitempty"`
	MemMB     int       `json:"memMb,omitempty"`
	RootUse   int       `json:"rootUsePct,omitempty"`
	Collected time.Time `json:"collected"`
}

// NetOSInfo is what a network device reported over SSH.
type NetOSInfo struct {
	Platform  string    `json:"platform"`
	Version   string    `json:"version,omitempty"`
	Model     string    `json:"model,omitempty"`
	Serial    string    `json:"serial,omitempty"`
	Uptime    string    `json:"uptime,omitempty"`
	Collected time.Time `json:"collected"`
}

// ConfigInfo summarizes a config backup; the text itself lives only in
// the encrypted vault.
type ConfigInfo struct {
	Platform string    `json:"platform"`
	Lines    int       `json:"lines"`
	SHA256   string    `json:"sha256"`
	Captured time.Time `json:"captured"`
	Changed  bool      `json:"changed"` // differs from the previous backup
	Issues   []string  `json:"issues,omitempty"`
}

// Link is an edge on the topology map.
type Link struct {
	A      string `json:"a"` // device id
	B      string `json:"b"`
	APort  string `json:"aPort,omitempty"`
	BPort  string `json:"bPort,omitempty"`
	Kind   string `json:"kind"` // lldp | cdp | fdb | gateway | inferred
	Speed  int64  `json:"speedMbps,omitempty"`
	VLANs  []int  `json:"vlans,omitempty"`
	Weight int    `json:"weight,omitempty"`
}

// Severity of a finding/alert.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Finding is a posture issue produced by the assessment engine.
type Finding struct {
	ID          string   `json:"id"`
	Check       string   `json:"check"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
	Devices     []string `json:"devices,omitempty"` // device ids
}

// Event is a timestamped log/alert line streamed to the dashboard.
type Event struct {
	Time     time.Time `json:"time"`
	Severity Severity  `json:"severity"`
	Source   string    `json:"source"`
	Message  string    `json:"message"`
	DeviceID string    `json:"deviceId,omitempty"`
}

// Flow is an aggregated NetFlow/IPFIX conversation.
type Flow struct {
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
	SrcPort  int       `json:"srcPort"`
	DstPort  int       `json:"dstPort"`
	Proto    int       `json:"proto"`
	Bytes    uint64    `json:"bytes"`
	Packets  uint64    `json:"packets"`
	Exporter string    `json:"exporter"`
	LastSeen time.Time `json:"lastSeen"`
}

// FlowSummary is what the Traffic view shows.
type FlowSummary struct {
	Listening     bool              `json:"listening"`
	ListenAddr    string            `json:"listenAddr,omitempty"`
	Exporters     map[string]uint64 `json:"exporters"`
	TotalBytes    uint64            `json:"totalBytes"`
	TotalPackets  uint64            `json:"totalPackets"`
	TotalFlows    uint64            `json:"totalFlows"`
	Protocols     map[string]uint64 `json:"protocols"`
	TopTalkers    []Talker          `json:"topTalkers"`
	TopApps       []Talker          `json:"topApps"`
	Conversations []Flow            `json:"conversations"`
	Series        []RatePoint       `json:"series"`
	Errors        map[string]uint64 `json:"errors,omitempty"`
	Versions      map[string]uint64 `json:"versions,omitempty"`
}

// Talker is a host or application ranked by bytes.
type Talker struct {
	Key     string `json:"key"`
	Label   string `json:"label,omitempty"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}

// RatePoint is one sample of a time series.
type RatePoint struct {
	T     int64   `json:"t"` // unix ms
	Value float64 `json:"v"`
	Extra float64 `json:"x,omitempty"`
}

// StormStatus is the live Storm Guard view.
type StormStatus struct {
	Running        bool        `json:"running"`
	Interface      string      `json:"interface,omitempty"`
	Error          string      `json:"error,omitempty"`
	Current        PPSSample   `json:"current"`
	Series         []PPSSample `json:"series"`
	Peak           PPSSample   `json:"peak"`
	TopBroadcaster []Talker    `json:"topBroadcasters"`
	STP            STPInfo     `json:"stp"`
	State          string      `json:"state"` // ok | warning | storm
	WarnPPS        int         `json:"warnPps"`
	CritPPS        int         `json:"critPps"`
	DuplicateRate  float64     `json:"duplicateRate"`
}

// PPSSample is one second of traffic accounting.
type PPSSample struct {
	T         int64 `json:"t"`
	Total     int   `json:"total"`
	Broadcast int   `json:"broadcast"`
	Multicast int   `json:"multicast"`
	Unicast   int   `json:"unicast"`
	ARP       int   `json:"arp"`
	Bytes     int   `json:"bytes"`
	Dups      int   `json:"dups"`
}

// STPInfo summarizes spanning-tree BPDUs heard on the wire.
type STPInfo struct {
	Seen            bool      `json:"seen"`
	Protocol        string    `json:"protocol,omitempty"` // STP / RSTP / MSTP
	RootBridge      string    `json:"rootBridge,omitempty"`
	RootPriority    int       `json:"rootPriority,omitempty"`
	RootCost        int       `json:"rootCost,omitempty"`
	SenderBridge    string    `json:"senderBridge,omitempty"`
	TopologyChanges int       `json:"topologyChanges"`
	LastTC          time.Time `json:"lastTc,omitempty"`
	RootChanges     int       `json:"rootChanges"`
	BPDUs           int       `json:"bpdus"`
}

// DHCPServer seen offering leases.
type DHCPServer struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac,omitempty"`
	Router   string    `json:"router,omitempty"`
	DNS      []string  `json:"dns,omitempty"`
	Domain   string    `json:"domain,omitempty"`
	Offers   int       `json:"offers"`
	LastSeen time.Time `json:"lastSeen"`
}

// Subnet discovered or scanned.
type Subnet struct {
	CIDR      string `json:"cidr"`
	Gateway   string `json:"gateway,omitempty"`
	Interface string `json:"interface,omitempty"`
	Local     bool   `json:"local"`
	Hosts     int    `json:"hosts"`
}

// Capabilities reports what this host/OS/privilege level allows.
type Capabilities struct {
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Privileged   bool     `json:"privileged"`
	RawCapture   bool     `json:"rawCapture"`
	CaptureNote  string   `json:"captureNote,omitempty"`
	ICMPMode     string   `json:"icmpMode"` // raw | datagram | windows-api | tcp-only
	Interfaces   []IfInfo `json:"interfaces"`
	DefaultIface string   `json:"defaultIface,omitempty"`
	Hostname     string   `json:"hostname"`
}

// IfInfo is a local interface the user can pick.
type IfInfo struct {
	Name    string   `json:"name"`
	Display string   `json:"display"`
	MAC     string   `json:"mac,omitempty"`
	Addrs   []string `json:"addrs"`
	Up      bool     `json:"up"`
	Gateway string   `json:"gateway,omitempty"`
}

// ScanConfig is what the user submits to start an assessment.
type ScanConfig struct {
	Site           string        `json:"site"`
	Interface      string        `json:"interface"`
	Targets        []string      `json:"targets"` // CIDRs, ranges or IPs
	Communities    []string      `json:"communities"`
	SNMPv3         []SNMPv3Cred  `json:"snmpv3,omitempty"`
	Ports          string        `json:"ports"` // "default" | "top" | "1-1024,3389"
	PassiveSeconds int           `json:"passiveSeconds"`
	ZeroFootprint  bool          `json:"zeroFootprint"` // passive only, never transmit
	SkipARP        bool          `json:"skipArp,omitempty"`
	SkipPorts      bool          `json:"skipPorts,omitempty"`
	SkipSNMP       bool          `json:"skipSnmp,omitempty"`
	UseVault       bool          `json:"useVault,omitempty"`
	Rate           int           `json:"rate"` // packets/s for sweeps
	Timeout        time.Duration `json:"timeoutMs"`
}

// SNMPv3Cred is a USM credential. Secrets are never written to disk.
type SNMPv3Cred struct {
	User      string `json:"user"`
	AuthProto string `json:"authProto"` // MD5|SHA|SHA256|SHA512
	AuthPass  string `json:"authPass"`
	PrivProto string `json:"privProto"` // DES|AES|AES256
	PrivPass  string `json:"privPass"`
}

// ScanStatus is the progress of the current/last scan.
type ScanStatus struct {
	Running  bool          `json:"running"`
	Phase    string        `json:"phase"`
	Progress float64       `json:"progress"` // 0..1
	Started  time.Time     `json:"started,omitempty"`
	Finished time.Time     `json:"finished,omitempty"`
	Message  string        `json:"message,omitempty"`
	Phases   []PhaseStatus `json:"phases"`
	Config   *ScanConfig   `json:"config,omitempty"`
}

// PhaseStatus is one stage of the pipeline.
type PhaseStatus struct {
	Name     string `json:"name"`
	State    string `json:"state"` // pending | running | done | skipped | error
	Detail   string `json:"detail,omitempty"`
	Duration int64  `json:"durationMs,omitempty"`
}

// Snapshot is the full saved state of an assessment.
type Snapshot struct {
	Version     string       `json:"version"`
	Site        string       `json:"site"`
	Generated   time.Time    `json:"generated"`
	Collector   string       `json:"collector"`
	Caps        Capabilities `json:"capabilities"`
	Subnets     []Subnet     `json:"subnets"`
	Devices     []*Device    `json:"devices"`
	Links       []Link       `json:"links"`
	Findings    []Finding    `json:"findings"`
	Score       int          `json:"score"`
	Grade       string       `json:"grade"`
	Events      []Event      `json:"events"`
	DHCPServers []DHCPServer `json:"dhcpServers"`
	VLANs       []VLAN       `json:"vlans"`
	Flows       FlowSummary  `json:"flows"`
	Storm       StormStatus  `json:"storm"`
	Scan        ScanStatus   `json:"scan"`
}
