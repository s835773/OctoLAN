// Package assess turns the inventory into a scored security & health
// posture: the findings an MSP tech walks a customer through.
package assess

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/s835773/OctoLAN/internal/model"
)

// Input is everything the checks look at.
type Input struct {
	Devices     []*model.Device
	DHCPServers []model.DHCPServer
	DuplicateIP map[string][]string
	Storm       model.StormStatus
	Flows       model.FlowSummary
	VLANs       []model.VLAN
	Now         time.Time
}

type builder struct {
	in    Input
	finds map[string]*model.Finding
}

func (b *builder) add(check string, sev model.Severity, cat, title, detail, fix string, devID string) {
	f := b.finds[check]
	if f == nil {
		f = &model.Finding{ID: check, Check: check, Severity: sev, Category: cat, Title: title, Detail: detail, Remediation: fix}
		b.finds[check] = f
	}
	if devID != "" {
		for _, d := range f.Devices {
			if d == devID {
				return
			}
		}
		f.Devices = append(f.Devices, devID)
	}
}

func hasPort(d *model.Device, p int) bool {
	for _, x := range d.Ports {
		if x.Port == p {
			return true
		}
	}
	return false
}

func portBanner(d *model.Device, p int) string {
	for _, x := range d.Ports {
		if x.Port == p {
			return x.Banner
		}
	}
	return ""
}

func isInfra(d *model.Device) bool {
	switch d.Type {
	case model.TypeRouter, model.TypeSwitch, model.TypeFirewall, model.TypeAccessPoint, model.TypeUPS:
		return true
	}
	return false
}

// Run evaluates every check and returns findings (most severe first), a
// 0-100 score and a letter grade.
func Run(in Input) ([]model.Finding, int, string) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	b := &builder{in: in, finds: map[string]*model.Finding{}}
	alive := 0
	unknown := 0
	for _, d := range in.Devices {
		if d.IsSelf {
			continue
		}
		if d.Alive {
			alive++
		}
		b.deviceChecks(d)
		if d.Type == model.TypeUnknown && d.Alive {
			unknown++
			b.add("unidentified-devices", model.SevInfo, "Inventory", "Unidentified devices",
				"These devices answered on the network but OctoLAN could not determine what they are (no hostname, open services, SNMP or vendor match).",
				"Identify and label each device. Unknown devices are a common source of shadow IT and unmanaged risk.", d.ID)
		}
	}
	b.networkChecks()

	out := make([]model.Finding, 0, len(b.finds))
	for _, f := range b.finds {
		out = append(out, *f)
	}
	rank := map[model.Severity]int{model.SevCritical: 0, model.SevHigh: 1, model.SevMedium: 2, model.SevLow: 3, model.SevInfo: 4}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		if len(out[i].Devices) != len(out[j].Devices) {
			return len(out[i].Devices) > len(out[j].Devices)
		}
		return out[i].Title < out[j].Title
	})
	score := score(out, alive)
	return out, score, grade(score)
}

func (b *builder) deviceChecks(d *model.Device) {
	// --- Insecure / cleartext management ---
	if hasPort(d, 23) {
		b.add("telnet", model.SevHigh, "Insecure protocols", "Telnet enabled",
			"Telnet sends credentials and sessions in cleartext. Anyone on the network path can capture admin passwords.",
			"Disable Telnet and use SSH. On Cisco: `line vty 0 15` → `transport input ssh`.", d.ID)
	}
	if hasPort(d, 21) {
		b.add("ftp", model.SevMedium, "Insecure protocols", "FTP service exposed",
			"FTP transfers credentials and files unencrypted.",
			"Replace with SFTP/FTPS, or disable the service if it is not needed.", d.ID)
	}
	if hasPort(d, 4786) {
		b.add("cisco-smart-install", model.SevCritical, "Vulnerable services", "Cisco Smart Install exposed (TCP 4786)",
			"Smart Install allows unauthenticated configuration changes and has been widely exploited (CVE-2018-0171).",
			"Run `no vstack` on every switch.", d.ID)
	}
	if hasPort(d, 2375) {
		b.add("docker-api", model.SevCritical, "Vulnerable services", "Unauthenticated Docker API (TCP 2375)",
			"The Docker daemon is reachable without TLS or authentication, which grants root on the host.",
			"Bind the Docker API to a local socket or require mutual TLS on 2376.", d.ID)
	}
	for _, p := range []int{6379, 9200, 27017} {
		if hasPort(d, p) {
			b.add("open-datastore", model.SevHigh, "Vulnerable services", "Database/datastore reachable on the LAN",
				"Redis, Elasticsearch or MongoDB is listening on the network. These are often deployed without authentication.",
				"Restrict to localhost or an application VLAN and enable authentication.", d.ID)
		}
	}
	if hasPort(d, 5900) {
		b.add("vnc", model.SevMedium, "Remote access", "VNC remote desktop exposed",
			"VNC is frequently configured with weak or no passwords and usually lacks encryption.",
			"Remove VNC or restrict it to a management network; use the RMM's remote-control tool instead.", d.ID)
	}
	if hasPort(d, 3389) && d.Type != model.TypeServer {
		b.add("rdp-workstations", model.SevLow, "Remote access", "RDP enabled on workstations",
			"Remote Desktop listening on endpoints widens the lateral-movement surface for ransomware.",
			"Disable RDP on workstations or restrict it by firewall to admin jump hosts; require NLA.", d.ID)
	}
	if hasPort(d, 7547) {
		b.add("tr069", model.SevMedium, "Vulnerable services", "TR-069 management port exposed",
			"ISP remote-management (CWMP) is reachable internally; it has a long history of exploits.",
			"Ask the ISP to restrict CWMP or replace the CPE with a managed firewall.", d.ID)
	}
	if hasPort(d, 1723) {
		b.add("pptp", model.SevMedium, "Insecure protocols", "PPTP VPN enabled",
			"PPTP's MS-CHAPv2 authentication is broken and should not be used.",
			"Migrate to IKEv2/IPsec, WireGuard or an SSL VPN.", d.ID)
	}
	if isInfra(d) || d.Type == model.TypePrinter || d.Type == model.TypeUPS || d.Type == model.TypeNAS || d.Type == model.TypeCamera {
		for _, p := range []int{80, 8080, 81} {
			if hasPort(d, p) && !hasPort(d, 443) && !hasPort(d, 8443) {
				banner := strings.ToLower(portBanner(d, p))
				if !strings.Contains(banner, " 301") && !strings.Contains(banner, " 302") && !strings.Contains(banner, " 308") {
					b.add("http-mgmt", model.SevMedium, "Insecure protocols", "Management web UI over plain HTTP",
						"Infrastructure devices offer their admin page without HTTPS, exposing admin credentials on the wire.",
						"Enable HTTPS-only management and disable the HTTP listener.", d.ID)
					break
				}
			}
		}
	}

	// --- SNMP ---
	if d.SNMP != nil {
		if d.SNMP.DefaultComm {
			b.add("snmp-default-community", model.SevHigh, "Credentials", "SNMP responds to a default community string",
				"The device answers SNMP with 'public' or 'private'. Anyone on the LAN can read its configuration details; 'private' may allow writes.",
				"Change community strings to long random values, restrict SNMP by ACL to the monitoring host, or move to SNMPv3 authPriv.", d.ID)
		}
		if d.SNMP.Version == "v1" || d.SNMP.Version == "v2c" {
			b.add("snmp-v2", model.SevLow, "Insecure protocols", "SNMP v1/v2c in use",
				"Community strings travel in cleartext.",
				"Migrate monitoring to SNMPv3 with authentication and privacy (SHA/AES).", d.ID)
		}
	}

	// --- SMB / Windows ---
	if d.SMB != nil {
		if d.SMB.SMB1 {
			b.add("smbv1", model.SevHigh, "Vulnerable services", "SMBv1 enabled",
				"SMBv1 is the protocol abused by WannaCry/NotPetya (EternalBlue) and is deprecated by Microsoft.",
				"Disable SMB1: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`; on NAS devices set minimum protocol to SMB2.", d.ID)
		}
		if !d.SMB.SigningReq && d.Type == model.TypeServer {
			b.add("smb-signing", model.SevMedium, "Hardening", "SMB signing not required on servers",
				"Without required signing, SMB relay attacks (e.g. NTLM relay) can impersonate users against these servers.",
				"Set 'Microsoft network server: Digitally sign communications (always)' via GPO.", d.ID)
		}
	}
	if d.OS.EOL {
		b.add("eol-os", model.SevHigh, "Lifecycle", "End-of-life operating system",
			"These devices run an OS or firmware past vendor end of support and no longer receive security patches.",
			"Plan upgrade or replacement; isolate on a restricted VLAN in the meantime.", d.ID)
	}
	if b2 := strings.ToLower(portBanner(d, 22)); b2 != "" && oldOpenSSH(b2) {
		b.add("old-ssh", model.SevLow, "Lifecycle", "Outdated SSH server",
			"The SSH banner reports an OpenSSH release older than 8.0 with known vulnerabilities.",
			"Update the device firmware/OS.", d.ID)
	}

	// --- TLS certificates ---
	for _, t := range d.TLS {
		days := t.NotAfter.Sub(b.in.Now).Hours() / 24
		switch {
		case days < 0:
			b.add("tls-expired", model.SevMedium, "Certificates", "Expired TLS certificates",
				"Services are presenting certificates that have already expired; users learn to click through warnings.",
				"Renew the certificates (or automate with ACME/internal CA).", d.ID)
		case days < 30:
			b.add("tls-expiring", model.SevLow, "Certificates", "TLS certificates expiring within 30 days",
				"Certificates will expire soon and cause outages or browser warnings.",
				"Renew before expiry.", d.ID)
		}
		if t.SelfSigned && (isInfra(d) || d.Type == model.TypeServer || d.Type == model.TypeHypervisor || d.Type == model.TypeNAS) {
			b.add("tls-self-signed", model.SevInfo, "Certificates", "Self-signed certificates on management interfaces",
				"Self-signed certificates can't be distinguished from an attacker's certificate by users.",
				"Issue certificates from an internal CA and distribute the root via GPO/MDM.", d.ID)
		}
		if t.Version == "TLS 1.0" || t.Version == "TLS 1.1" || t.Version == "SSLv3" {
			b.add("tls-legacy", model.SevMedium, "Insecure protocols", "Legacy TLS (1.0/1.1) negotiated",
				"These services still negotiate deprecated TLS versions.",
				"Disable TLS 1.0/1.1 and require TLS 1.2+.", d.ID)
		}
	}

	// --- UPnP ---
	for _, s := range d.Services {
		if s.Type == "ssdp" && (d.IsGateway || d.Type == model.TypeRouter || d.Type == model.TypeFirewall) {
			b.add("upnp-gateway", model.SevMedium, "Hardening", "UPnP enabled on the gateway",
				"UPnP lets any internal device open inbound ports on the firewall without admin approval.",
				"Disable UPnP/NAT-PMP on the edge device.", d.ID)
			break
		}
	}

	// --- Latency / health ---
	if d.RTTMicro > 50_000 && d.Alive && !d.IsGateway {
		b.add("high-latency", model.SevLow, "Performance", "High LAN latency (>50 ms)",
			"These local devices responded slowly, which can indicate congestion, Wi-Fi issues or an overloaded device.",
			"Check interface errors and utilisation along the path; review Wi-Fi channel plan.", d.ID)
	}
	for _, ifc := range d.Interfaces {
		if ifc.InErrors+ifc.OutErrors > 1000 && ifc.OperUp {
			b.add("interface-errors", model.SevMedium, "Performance", "Switch/router interfaces with errors",
				"Interfaces report a high error count (CRC/frame errors), commonly a bad cable, duplex mismatch or failing optic.",
				"Check cabling and duplex settings on the listed devices' ports.", d.ID)
			break
		}
	}
	if d.SNMP != nil && d.SNMP.SysUpTime > 365*24*3600 {
		b.add("long-uptime", model.SevLow, "Lifecycle", "Infrastructure not rebooted in over a year",
			"Uptime over a year usually means firmware has not been patched.",
			"Schedule firmware updates in a maintenance window.", d.ID)
	}
	if d.SNMP != nil && isInfra(d) && d.SNMP.SysName == "" {
		b.add("no-sysname", model.SevInfo, "Documentation", "Network devices without hostnames",
			"Unnamed infrastructure makes troubleshooting and documentation harder.",
			"Set a hostname and sysLocation on every network device.", d.ID)
	}
}

func oldOpenSSH(b string) bool {
	i := strings.Index(b, "openssh_")
	if i < 0 {
		return false
	}
	var major, minor int
	if _, err := fmt.Sscanf(b[i+8:], "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major < 8
}

func (b *builder) networkChecks() {
	in := b.in
	if len(in.DHCPServers) > 1 {
		var ips []string
		for _, s := range in.DHCPServers {
			ips = append(ips, s.IP)
		}
		b.add("rogue-dhcp", model.SevHigh, "Network", "Multiple DHCP servers on one segment",
			"More than one DHCP server answered: "+strings.Join(ips, ", ")+". A rogue DHCP server can redirect clients' gateway/DNS (man-in-the-middle) or cause outages.",
			"Identify the unauthorised server; enable DHCP snooping on access switches.", "")
	}
	for ip, macs := range in.DuplicateIP {
		b.add("duplicate-ip", model.SevHigh, "Network", "Duplicate IP addresses",
			fmt.Sprintf("%s is claimed by %s (and possibly others). Duplicate IPs cause intermittent outages and can indicate ARP spoofing.", ip, strings.Join(macs, " and ")),
			"Fix static assignments / DHCP reservations; enable Dynamic ARP Inspection.", "")
	}
	st := in.Storm
	switch {
	case st.State == "storm" || st.Peak.Broadcast+st.Peak.Multicast >= max(st.CritPPS, 5000):
		b.add("broadcast-storm", model.SevCritical, "Network", "Broadcast storm detected",
			fmt.Sprintf("Peak broadcast+multicast reached %d packets/sec with %d repeated frames: consistent with a layer-2 loop.", st.Peak.Broadcast+st.Peak.Multicast, st.Peak.Dups),
			"Enable spanning tree (RSTP) and BPDU guard on edge ports; look for unmanaged switches cabled in a loop.", "")
	case st.Peak.Broadcast+st.Peak.Multicast >= max(st.WarnPPS, 1000):
		b.add("broadcast-high", model.SevMedium, "Network", "High broadcast/multicast load",
			fmt.Sprintf("Peak broadcast+multicast reached %d packets/sec on the assessed segment.", st.Peak.Broadcast+st.Peak.Multicast),
			"Segment large flat networks into VLANs; review chatty devices in the top broadcasters list.", "")
	}
	if st.STP.TopologyChanges >= 3 {
		b.add("stp-instability", model.SevMedium, "Network", "Frequent spanning-tree topology changes",
			fmt.Sprintf("%d topology changes were observed during the assessment, which flushes MAC tables and causes brief outages.", st.STP.TopologyChanges),
			"Enable PortFast/edge-port on access ports and find the flapping link.", "")
	}
	if st.STP.RootChanges > 0 {
		b.add("stp-root-change", model.SevHigh, "Network", "Spanning-tree root bridge changed",
			"The root bridge changed during the assessment. A switch with a low priority (or an attacker) may be taking over the root role.",
			"Pin the root by setting priority 4096 on the core switch and enable root guard on access uplinks.", "")
	}
	if st.STP.Seen && st.STP.RootPriority == 32768 {
		b.add("stp-default-priority", model.SevLow, "Hardening", "Spanning-tree root uses default priority",
			"The root bridge was elected by MAC address, not design, so the 'oldest' switch may be root.",
			"Set an explicit bridge priority on the intended core switch.", "")
	}
	if st.Running && !st.STP.Seen && len(in.Devices) > 15 {
		b.add("stp-not-seen", model.SevInfo, "Network", "No spanning-tree BPDUs heard",
			"No STP BPDUs reached the assessment port. Either the port has BPDU filtering, or the network has no loop protection.",
			"Confirm RSTP is enabled across switches.", "")
	}
	// Flat network: many devices, single subnet, no VLANs.
	if len(in.Devices) > 60 && len(in.VLANs) <= 1 {
		b.add("flat-network", model.SevMedium, "Architecture", "Flat network: no VLAN segmentation detected",
			fmt.Sprintf("%d devices share a single broadcast domain. Printers, cameras, IoT, guests and servers can all reach each other.", len(in.Devices)),
			"Segment into VLANs (users, servers, voice, printers/IoT, guest, management) with inter-VLAN firewall rules.", "")
	}
	iot := 0
	for _, d := range in.Devices {
		if d.Type == model.TypeIoT || d.Type == model.TypeCamera || d.Type == model.TypeMedia {
			iot++
		}
	}
	if iot >= 3 && len(in.VLANs) <= 1 {
		b.add("iot-not-isolated", model.SevMedium, "Architecture", "IoT / cameras share the user network",
			fmt.Sprintf("%d IoT, camera or media devices are on the same network as business systems.", iot),
			"Move IoT and cameras to an isolated VLAN with internet-only or NVR-only access.", "")
	}
}

var weights = map[model.Severity]float64{
	model.SevCritical: 25, model.SevHigh: 15, model.SevMedium: 4, model.SevLow: 1.5, model.SevInfo: 0,
}

// score turns findings into 0-100. Penalties compound with diminishing
// returns (so a bad network lands around 30-50, not 0, and remains
// comparable after fixes), and the worst severity caps the result: any
// critical issue means at most a D, any high issue at most a C.
func score(fs []model.Finding, alive int) int {
	penalty := 0.0
	worst := model.SevInfo
	rank := map[model.Severity]int{model.SevCritical: 4, model.SevHigh: 3, model.SevMedium: 2, model.SevLow: 1, model.SevInfo: 0}
	for _, f := range fs {
		mult := 1.0
		if n := len(f.Devices); n > 1 {
			mult = 1 + math.Log2(float64(n))*0.5
		}
		penalty += weights[f.Severity] * mult
		if rank[f.Severity] > rank[worst] {
			worst = f.Severity
		}
	}
	s := 100 * math.Exp(-penalty/150)
	switch worst {
	case model.SevCritical:
		s = math.Min(s, 69)
	case model.SevHigh:
		s = math.Min(s, 79)
	}
	_ = alive
	return int(math.Round(s))
}

func grade(s int) string {
	switch {
	case s >= 90:
		return "A"
	case s >= 80:
		return "B"
	case s >= 70:
		return "C"
	case s >= 60:
		return "D"
	}
	return "F"
}
