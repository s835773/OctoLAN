package discovery

import (
	"fmt"
	"slices"
	"strings"

	"github.com/s835773/OcuLAN/internal/model"
)

// sysObjectID enterprise numbers → vendor family.
var enterpriseVendor = map[string]string{
	"9": "Cisco", "11": "HPE", "43": "3Com", "171": "D-Link", "232": "HPE/Compaq",
	"311": "Microsoft", "674": "Dell", "1916": "Extreme", "1991": "Brocade",
	"2011": "Huawei", "2272": "Nortel/Avaya", "2636": "Juniper", "3375": "F5",
	"4526": "Netgear", "5624": "Enterasys", "6027": "Dell Force10", "6486": "Alcatel-Lucent",
	"8072": "Net-SNMP (Linux)", "9148": "Palo Alto", "10002": "Ubiquiti", "11863": "TP-Link",
	"12356": "Fortinet", "14179": "Cisco WLC", "14823": "Aruba", "14988": "MikroTik",
	"25053": "Ruckus", "25461": "Palo Alto", "29671": "Cisco Meraki", "30065": "Arista",
	"318": "APC", "534": "Eaton", "2620": "Check Point", "8741": "SonicWall",
	"6876": "VMware", "6574": "Synology", "24681": "QNAP", "41112": "Ubiquiti",
	"367": "Ricoh", "1602": "Canon", "2435": "Brother", "1347": "Kyocera", "253": "Xerox",
	"641": "Lexmark", "21839": "Sophos", "3076": "Cisco ASA", "4413": "Broadcom",
	"36601": "Netgate", "12325": "pfSense/FreeBSD", "13191": "OneAccess", "40310": "Cumulus",
	"39324": "Hikvision", "50001": "Grandstream", "6889": "Avaya", "5951": "Netscaler",
	"7244": "Quanta", "45064": "SonicWall", "35265": "Eltek", "2021": "UCD-SNMP (Linux)",
	"17163": "Riverbed", "26928": "Aerohive", "29601": "Mitel", "1588": "Brocade", "890": "Zyxel",
	"8691": "Moxa", "4329": "Siemens", "25506": "H3C", "3224": "Juniper NetScreen", "52642": "Sophos",
}

// Classify infers device type and OS from every piece of evidence.
// Called after each discovery phase; later evidence refines earlier.
func Classify(d *model.Device) {
	vendor := strings.ToLower(d.Vendor)
	descr, oid, services := "", "", 0
	if d.SNMP != nil {
		descr = strings.ToLower(d.SNMP.SysDescr)
		oid = d.SNMP.SysObjectID
		services = d.SNMP.SysServices
	}
	host := strings.ToLower(d.Hostname)
	banners := strings.ToLower(bannerText(d))
	svc := strings.ToLower(serviceText(d))
	has := func(p int) bool {
		return slices.ContainsFunc(d.Ports, func(x model.Port) bool { return x.Port == p })
	}
	hasAny := func(s string, subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}

	ev := []string{}
	t := model.TypeUnknown
	set := func(nt model.DeviceType, why string) {
		if t == model.TypeUnknown {
			t = nt
			ev = append(ev, why)
		}
	}

	// --- SNMP is the strongest signal ---
	entVendor := ""
	if oid != "" {
		parts := strings.Split(strings.TrimPrefix(oid, "1.3.6.1.4.1."), ".")
		if len(parts) > 0 && strings.HasPrefix(oid, "1.3.6.1.4.1.") {
			entVendor = enterpriseVendor[parts[0]]
		}
	}
	if d.SNMP != nil {
		switch {
		case hasAny(descr, "fortigate", "palo alto", "pan-os", "sonicwall", "sonicos", "asa ", "adaptive security", "firepower", "pfsense", "opnsense", "watchguard", "sophos", "check point", "meraki mx", "fortios", "untangle"):
			set(model.TypeFirewall, "SNMP sysDescr names a firewall")
		case hasAny(descr, "access point", "aironet", "unifi ap", "uap-", " u6-", "u7-", "instant on ap", "aruba ap", "ruckus", "meraki mr", "cap ac", "eap"):
			set(model.TypeAccessPoint, "SNMP sysDescr names an access point")
		case hasAny(descr, "ups", "smart-ups", "network management card", "powerware") || strings.HasPrefix(d.Model, "UPS") || strings.HasPrefix(entVendor, "APC") || entVendor == "Eaton":
			set(model.TypeUPS, "SNMP identifies a UPS/PDU")
		case hasAny(descr, "printer", "laserjet", "officejet", "imagerunner", "bizhub", "workcentre", "versalink", "ecosys", "mfc-", "hl-", "taskalfa", "jetdirect", "ricoh", "lexmark", "xerox") || strings.HasPrefix(d.Notes, "Printer"):
			set(model.TypePrinter, "SNMP identifies a printer")
		case hasAny(descr, "synology", "diskstation", "qnap", "readynas", "truenas", "freenas", "netapp", "isilon"):
			set(model.TypeNAS, "SNMP sysDescr names a storage appliance")
		case hasAny(descr, "vmware esxi", "proxmox", "hyper-v", "xenserver", "nutanix"):
			set(model.TypeHypervisor, "SNMP sysDescr names a hypervisor")
		case hasAny(descr, "switch", "catalyst", "nexus", "procurve", "aruba", "comware", "edgeswitch", "unifi switch", "usw-", "powerconnect", "dell networking", "dell emc networking", "cumulus", "arista", "junos ex", "ex2300", "ex3400", "ex4300", "netgear", "tl-sg", "dgs-", "sg350", "sg300", "cbs350", "icx", "fastiron", "routeros crs", "mikrotik crs", "omniswitch", "s5700", "s6720"):
			set(model.TypeSwitch, "SNMP sysDescr names a switch")
		case hasAny(descr, "router", "routeros", "isr", "ios-xe", "edgeos", "edgerouter", "vyos", "junos mx", "junos srx", "asr"):
			set(model.TypeRouter, "SNMP sysDescr names a router")
		case hasAny(descr, "windows"):
			if hasAny(descr, "server") || has(88) || has(389) {
				set(model.TypeServer, "SNMP reports Windows Server")
			} else {
				set(model.TypeWorkstation, "SNMP reports Windows")
			}
		case services&0x04 != 0 && services&0x02 != 0 && len(d.FDB) > 0:
			set(model.TypeSwitch, "SNMP sysServices: L2+L3 with a bridge table")
		case services&0x04 != 0 && len(d.Interfaces) > 2:
			set(model.TypeRouter, "SNMP sysServices: layer 3 forwarding")
		case services&0x02 != 0 || len(d.FDB) > 0:
			set(model.TypeSwitch, "SNMP sysServices/bridge table: layer 2 forwarding")
		}
	}

	// --- Apple / Bonjour model identifiers (_device-info "model=") ---
	if m := strings.ToLower(d.Model); m != "" {
		switch {
		case strings.HasPrefix(m, "xserve") || strings.HasPrefix(m, "rackmac"):
			// Samba/NAS boxes advertise themselves as Xserve for Time Machine.
			set(model.TypeNAS, "Bonjour model "+d.Model+" (SMB/Time Machine server)")
		case strings.HasPrefix(m, "appletv") || strings.HasPrefix(m, "audioaccessory"):
			set(model.TypeMedia, "Bonjour model "+d.Model+" (Apple TV / HomePod)")
		case strings.HasPrefix(m, "iphone") || strings.HasPrefix(m, "ipad") || strings.HasPrefix(m, "ipod"):
			set(model.TypeMobile, "Bonjour model "+d.Model)
		case appleMacModel(m):
			set(model.TypeWorkstation, "Bonjour model "+d.Model+" (Mac)")
		}
	}
	if hasAny(svc, "unifi os") || hasAny(banners, "title: unifi os") {
		if d.IsGateway {
			set(model.TypeFirewall, "UniFi OS gateway console")
		}
	}

	// --- Neighbours that advertise capabilities about themselves are
	// handled by topology; here use ports, banners, mDNS, vendor. ---
	switch {
	case has(9100) || has(515) || has(631) && !has(22) || hasAny(svc, "_ipp._tcp", "_pdl-datastream", "_printer._tcp") || hasAny(banners, "laserjet", "officejet", "printer", "epson", "brother", "kyocera", "ricoh", "xerox", "lexmark", "canon"):
		set(model.TypePrinter, "printer ports/services (9100/IPP/LPD)")
	case has(554) && hasAny(vendor+banners, "hikvision", "dahua", "axis", "hanwha", "uniview", "amcrest", "reolink", "vivotek", "camera", "ipc", "nvr", "dvr", "verkada", "avigilon"):
		set(model.TypeCamera, "RTSP plus a surveillance vendor/banner")
	case hasAny(vendor, "hikvision", "dahua", "axis communications", "hanwha", "vivotek", "reolink", "uniview", "verkada", "avigilon", "mobotix"):
		set(model.TypeCamera, "surveillance hardware vendor")
	case has(5060) || hasAny(vendor, "polycom", "yealink", "grandstream", "snom", "mitel", "avaya", "cisco spa", "poly", "fanvil", "obihai") || hasAny(banners, "polycom", "yealink", "grandstream"):
		set(model.TypePhone, "SIP port or VoIP phone vendor")
	case hasAny(banners, "fortigate", "fortinet", "sonicwall", "pfsense", "opnsense", "watchguard", "sophos", "palo alto", "global protect", "globalprotect") || hasAny(vendor, "fortinet", "sonicwall", "palo alto", "watchguard", "sophos", "netgate", "check point", "barracuda"):
		set(model.TypeFirewall, "firewall vendor or admin page")
	case has(8291) || hasAny(vendor, "mikrotik"):
		set(model.TypeRouter, "MikroTik RouterOS (Winbox)")
	case hasAny(banners, "synology", "diskstation", "qnap", "truenas", "readynas", "unraid") || hasAny(vendor, "synology", "qnap", "buffalo") || hasAny(svc, "_afpovertcp", "_smb._tcp") && hasAny(host, "nas", "diskstation"):
		set(model.TypeNAS, "storage appliance vendor/banner")
	case has(902) || has(8006) || hasAny(banners, "vmware esxi", "proxmox", "vmware vsphere"):
		set(model.TypeHypervisor, "ESXi (902) or Proxmox (8006)")
	case hasAny(vendor, "ubiquiti", "ruckus", "aruba", "cambium", "aerohive", "meraki", "engenius", "tp-link") && hasAny(banners+host, "uap", "u6-", "u7-", "ap-", "eap", "access point", "wap", "-ap"):
		set(model.TypeAccessPoint, "wireless vendor with AP naming")
	case hasAny(vendor, "apc", "american power", "schneider electric", "eaton", "cyberpower", "vertiv", "liebert", "tripp"):
		set(model.TypeUPS, "power-protection vendor")
	case hasAny(svc, "_googlecast", "_airplay", "_raop", "_spotify", "_sonos", "_roku", "_amzn") || hasAny(vendor, "sonos", "roku", "google", "amazon technologies", "samsung electronics", "lg electronics", "vizio"):
		set(model.TypeMedia, "media/casting service or vendor")
	case has(62078) || hasAny(svc, "_apple-mobdev", "_companion-link") || hasAny(host, "iphone", "ipad", "android", "galaxy", "pixel"):
		set(model.TypeMobile, "iOS sync port or phone hostname")
	case d.SMB != nil && (has(88) && has(389)):
		set(model.TypeServer, "Kerberos + LDAP: domain controller")
	case d.SMB != nil && strings.Contains(strings.ToLower(d.OS.Name), "server"):
		set(model.TypeServer, "Windows Server via SMB")
	case has(1433) || has(3306) || has(5432) || has(1521) || has(27017) || has(88) || has(389) || has(25) || has(2049) || has(3260):
		set(model.TypeServer, "server service listening (DB/LDAP/mail/storage)")
	case has(3389) || has(445) && has(135):
		set(model.TypeWorkstation, "Windows RDP/SMB endpoint")
	case hasAny(vendor, "espressif", "tuya", "shelly", "nest", "ecobee", "ring", "wyze", "philips lighting", "signify", "lifx", "sonoff", "particle", "raspberry"):
		set(model.TypeIoT, "IoT hardware vendor")
	case hasAny(vendor, "apple") && !d.RandomMAC:
		set(model.TypeWorkstation, "Apple hardware")
	case hasAny(vendor, "dell", "lenovo", "hewlett packard", "hp inc", "intel corporate", "microsoft", "asustek", "micro-star", "gigabyte", "framework", "acer"):
		set(model.TypeWorkstation, "PC hardware vendor")
	case d.RandomMAC:
		set(model.TypeMobile, "randomized (private) MAC address")
	case has(22) && !has(3389):
		set(model.TypeServer, "SSH-managed host")
	case hasAny(vendor, "cisco", "juniper", "arista", "hpe", "aruba", "netgear", "d-link", "zyxel", "ubiquiti"):
		set(model.TypeSwitch, "network equipment vendor")
	}
	if d.IsGateway && (t == model.TypeUnknown || t == model.TypeSwitch || t == model.TypeServer) {
		t = model.TypeRouter
		ev = append(ev, "default gateway for the subnet")
	}
	// The collector's own type is known; manual overrides stick.
	manual := slices.Contains(d.OS.Evidence, "type set manually")
	if !d.IsSelf && !manual && (d.Type == model.TypeUnknown || len(ev) > 0) {
		d.Type = t
	}

	inferOS(d, descr, entVendor, banners)
	if len(ev) > 0 {
		d.OS.Evidence = appendUnique(d.OS.Evidence, "type: "+ev[0])
	}
}

func inferOS(d *model.Device, descr, entVendor, banners string) {
	os := &d.OS
	setOS := func(family, name string, conf int, why string) {
		if conf > os.Confidence {
			os.Family, os.Confidence = family, conf
			if name != "" {
				os.Name = name
			}
			os.Evidence = appendUnique(os.Evidence, why)
		}
	}
	// 1. SMB/NTLM build number – exact Windows version.
	if d.SMB != nil && d.SMB.OSMajorMinor != "" {
		server := d.Type == model.TypeServer || hasPort(d, 88) || hasPort(d, 389) ||
			(d.SNMP != nil && strings.Contains(strings.ToLower(d.SNMP.SysDescr), "server"))
		name, eol := WindowsVersion(d.SMB.OSMajorMinor, d.SMB.OSBuild, server)
		setOS("Windows", fmt.Sprintf("%s (build %s)", name, d.SMB.OSBuild), 95, "SMB NTLM version "+d.SMB.OSMajorMinor+"."+d.SMB.OSBuild)
		os.EOL = eol
	}
	// 2. SNMP sysDescr.
	if descr != "" {
		raw := d.SNMP.SysDescr
		short := raw
		if len(short) > 80 {
			short = short[:80]
		}
		switch {
		case strings.Contains(descr, "cisco ios xe") || strings.Contains(descr, "ios-xe"):
			setOS("Cisco IOS XE", short, 90, "SNMP sysDescr")
		case strings.Contains(descr, "cisco nx-os"):
			setOS("Cisco NX-OS", short, 90, "SNMP sysDescr")
		case strings.Contains(descr, "cisco"):
			setOS("Cisco IOS", short, 90, "SNMP sysDescr")
			if strings.Contains(descr, "version 12.") || strings.Contains(descr, "version 15.0") {
				os.EOL = true
			}
		case strings.Contains(descr, "junos"):
			setOS("Junos", short, 90, "SNMP sysDescr")
		case strings.Contains(descr, "routeros"):
			setOS("RouterOS", short, 90, "SNMP sysDescr")
		case strings.Contains(descr, "fortigate") || strings.Contains(descr, "fortios"):
			setOS("FortiOS", short, 90, "SNMP sysDescr")
		case strings.Contains(descr, "windows"):
			setOS("Windows", short, 85, "SNMP sysDescr")
			for _, old := range []string{"windows 2000", "windows xp", "windows server 2003", "windows server 2008", "windows 7", "windows version 6.1", "windows version 6.0", "windows version 5."} {
				if strings.Contains(descr, old) {
					os.EOL = true
				}
			}
		case strings.Contains(descr, "linux"):
			setOS("Linux", short, 80, "SNMP sysDescr")
			if strings.Contains(descr, " 2.6.") || strings.Contains(descr, " 3.10.") {
				os.Evidence = appendUnique(os.Evidence, "very old Linux kernel")
			}
		case strings.Contains(descr, "freebsd"):
			setOS("FreeBSD", short, 80, "SNMP sysDescr")
		case strings.Contains(descr, "vmware"):
			setOS("VMware ESXi", short, 85, "SNMP sysDescr")
		default:
			fam := entVendor
			if fam == "" {
				fam = "Embedded"
			}
			setOS(fam, short, 60, "SNMP sysDescr")
		}
	}
	// 3. Service banners.
	switch {
	case strings.Contains(banners, "microsoft-iis") || strings.Contains(banners, "microsoft-httpapi"):
		setOS("Windows", "", 60, "Microsoft HTTP server banner")
	case strings.Contains(banners, "ubuntu"):
		setOS("Linux", "Ubuntu Linux", 65, "Ubuntu in service banner")
	case strings.Contains(banners, "debian"):
		setOS("Linux", "Debian Linux", 65, "Debian in service banner")
	case strings.Contains(banners, "openssh") && strings.Contains(banners, "freebsd"):
		setOS("FreeBSD", "", 65, "FreeBSD in SSH banner")
	case strings.Contains(banners, "dropbear"):
		setOS("Embedded Linux", "", 55, "Dropbear SSH (embedded Linux)")
	case strings.Contains(banners, "routeros") || strings.Contains(banners, "mikrotik"):
		setOS("RouterOS", "", 70, "MikroTik banner")
	}
	if hasPort(d, 62078) {
		setOS("iOS", "Apple iOS/iPadOS", 70, "iPhone sync port 62078")
	}
	if m := strings.ToLower(d.Model); m != "" {
		switch {
		case appleMacModel(m):
			setOS("macOS", "macOS ("+d.Model+")", 75, "Bonjour model "+d.Model)
		case strings.HasPrefix(m, "iphone") || strings.HasPrefix(m, "ipad"):
			setOS("iOS", "iOS/iPadOS ("+d.Model+")", 75, "Bonjour model "+d.Model)
		case strings.HasPrefix(m, "appletv"):
			setOS("tvOS", "tvOS ("+d.Model+")", 75, "Bonjour model "+d.Model)
		}
	}
	if s := strings.ToLower(serviceText(d)); strings.Contains(s, "_companion-link") || strings.Contains(s, "_asquic") || strings.Contains(s, "_apple-mobdev") {
		setOS("Apple", "Apple device (macOS/iOS)", 40, "Apple-only Bonjour services")
	}
	if strings.Contains(strings.ToLower(serviceText(d)), "_device-info") && strings.Contains(strings.ToLower(serviceText(d)), "mac") {
		setOS("macOS", "", 65, "mDNS device-info model")
	}
	// 4. TCP/IP stack heuristics (TTL + window).
	ttl := os.InitialTTL
	if ttl == 0 && d.TTL > 0 {
		ttl = normTTL(d.TTL)
		os.InitialTTL = ttl
	}
	switch ttl {
	case 128:
		setOS("Windows", "", 40, "initial TTL 128")
	case 64:
		guess := "Linux/Unix"
		if strings.Contains(strings.ToLower(d.Vendor), "apple") {
			guess = "macOS/iOS"
		}
		setOS(guess, "", 35, "initial TTL 64")
	case 255:
		setOS("Network OS", "", 35, "initial TTL 255 (routers, switches, Solaris)")
	}
	if os.Window != 0 {
		os.Evidence = appendUnique(os.Evidence, fmt.Sprintf("SYN-ACK window %d, DF=%v, MSS %d", os.Window, os.DF, os.MSS))
	}
}

func appleMacModel(m string) bool {
	for _, p := range []string{"macbook", "imac", "macmini", "macpro", "macstudio"} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	// Apple-silicon era identifiers: "Mac14,2", "Mac15,6" ...
	if strings.HasPrefix(m, "mac") && len(m) > 3 && m[3] >= '0' && m[3] <= '9' {
		return true
	}
	return false
}

// normTTL rounds an observed TTL up to the likely initial value.
func normTTL(t int) int {
	switch {
	case t <= 0:
		return 0
	case t <= 32:
		return 32
	case t <= 64:
		return 64
	case t <= 128:
		return 128
	}
	return 255
}

// NormTTL is exported for other packages.
func NormTTL(t int) int { return normTTL(t) }

func hasPort(d *model.Device, p int) bool {
	return slices.ContainsFunc(d.Ports, func(x model.Port) bool { return x.Port == p })
}

func bannerText(d *model.Device) string {
	var b strings.Builder
	for _, p := range d.Ports {
		b.WriteString(p.Banner)
		b.WriteByte(' ')
	}
	if d.SNMP != nil {
		b.WriteString(d.SNMP.SysDescr)
	}
	return b.String()
}

func serviceText(d *model.Device) string {
	var b strings.Builder
	for _, s := range d.Services {
		b.WriteString(s.Type + " " + s.Name + " " + s.Detail + " ")
	}
	return b.String()
}

func appendUnique(s []string, v string) []string {
	if v == "" || slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}
