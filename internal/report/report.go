// Package report renders the customer-facing assessment: a single
// self-contained HTML file (prints cleanly to PDF) plus CSV exports.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/ui"
)

// Label is the short display name for a device.
func Label(d *model.Device) string {
	if d.Hostname != "" {
		h := d.Hostname
		if i := strings.IndexByte(h, '.'); i > 0 && net.ParseIP(h) == nil {
			h = h[:i]
		}
		return h
	}
	if d.SNMP != nil && d.SNMP.SysName != "" {
		return d.SNMP.SysName
	}
	if len(d.IPs) > 0 {
		return d.IPs[0]
	}
	return d.MAC
}

type topoNode struct {
	ID       string           `json:"id"`
	Label    string           `json:"label"`
	IP       string           `json:"ip,omitempty"`
	Type     model.DeviceType `json:"type"`
	Vendor   string           `json:"vendor,omitempty"`
	Alive    bool             `json:"alive"`
	Self     bool             `json:"self,omitempty"`
	Gateway  bool             `json:"gateway,omitempty"`
	Findings int              `json:"findings,omitempty"`
	Worst    string           `json:"worst,omitempty"`
}

var sevRank = map[model.Severity]int{model.SevCritical: 5, model.SevHigh: 4, model.SevMedium: 3, model.SevLow: 2, model.SevInfo: 1}

// TopologyData is the node/link payload the map renderer consumes.
func TopologyData(devs []*model.Device, links []model.Link, finds []model.Finding) map[string]any {
	worst := map[string]string{}
	count := map[string]int{}
	for _, f := range finds {
		for _, id := range f.Devices {
			count[id]++
			if sevRank[f.Severity] > sevRank[model.Severity(worst[id])] {
				worst[id] = string(f.Severity)
			}
		}
	}
	nodes := make([]topoNode, 0, len(devs))
	for _, d := range devs {
		n := topoNode{ID: d.ID, Label: Label(d), Type: d.Type, Vendor: d.Vendor, Alive: d.Alive,
			Self: d.IsSelf, Gateway: d.IsGateway, Findings: count[d.ID], Worst: worst[d.ID]}
		if len(d.IPs) > 0 {
			n.IP = d.IPs[0]
		}
		nodes = append(nodes, n)
	}
	if links == nil {
		links = []model.Link{}
	}
	return map[string]any{"nodes": nodes, "links": links}
}

// ---- HTML report ----

type view struct {
	S          *model.Snapshot
	Generated  string
	Duration   string
	ByID       map[string]*model.Device
	SevCount   map[string]int
	TypeCount  []kv
	Alive      int
	Infra      int
	EOL        int
	WithSNMP   int
	Top        []model.Finding
	MapJSON    template.JS
	MapJS      template.JS
	GaugeDash  string
	GaugeColor string
	Summary    string
	Phases     []model.PhaseStatus
	Talkers    []model.Talker
	Apps       []model.Talker
	CredWin    int
	CredSSH    int
	CredCfg    int
	CredFailed int
}

type kv struct {
	K   string
	V   int
	Pct int
}

var funcs = template.FuncMap{
	"label": Label,
	"join":  strings.Join,
	"bytes": humanBytes,
	"ports": func(d *model.Device) string {
		var p []string
		for _, x := range d.Ports {
			p = append(p, fmt.Sprint(x.Port))
		}
		return strings.Join(p, " ")
	},
	"rtt": func(us int64) string {
		if us == 0 {
			return ""
		}
		if us < 1000 {
			return fmt.Sprintf("%d µs", us)
		}
		return fmt.Sprintf("%.1f ms", float64(us)/1000)
	},
	"title":  TypeLabel,
	"md":     inlineCode,
	"vendor": ShortVendor,
	"date": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format("2006-01-02")
	},
	"devname": func(byID map[string]*model.Device, id string) string {
		if d := byID[id]; d != nil {
			l := Label(d)
			if len(d.IPs) > 0 && l != d.IPs[0] {
				l += " (" + d.IPs[0] + ")"
			}
			return l
		}
		return id
	},
	"lower": strings.ToLower,
}

var tmpl = template.Must(template.New("report").Funcs(funcs).Parse(reportHTML))

// Write renders the HTML report.
func Write(w io.Writer, s *model.Snapshot) error {
	v := view{S: s, Generated: s.Generated.Format("Monday 2 January 2006, 15:04"), ByID: map[string]*model.Device{},
		SevCount: map[string]int{}, Phases: s.Scan.Phases}
	tc := map[string]int{}
	for _, d := range s.Devices {
		v.ByID[d.ID] = d
		if d.Alive {
			v.Alive++
		}
		switch d.Type {
		case model.TypeRouter, model.TypeSwitch, model.TypeFirewall, model.TypeAccessPoint:
			v.Infra++
		}
		if d.OS.EOL {
			v.EOL++
		}
		if d.SNMP != nil {
			v.WithSNMP++
		}
		if d.Windows != nil {
			v.CredWin++
		}
		if d.Linux != nil || d.NetOS != nil {
			v.CredSSH++
		}
		if d.Config != nil {
			v.CredCfg++
		}
		for _, t := range d.CredTries {
			if !t.OK {
				v.CredFailed++
				break
			}
		}
		tc[string(d.Type)]++
	}
	for k, n := range tc {
		v.TypeCount = append(v.TypeCount, kv{k, n, n * 100 / max(len(s.Devices), 1)})
	}
	sort.Slice(v.TypeCount, func(i, j int) bool { return v.TypeCount[i].V > v.TypeCount[j].V })
	for _, f := range s.Findings {
		v.SevCount[string(f.Severity)]++
		if f.Severity != model.SevInfo && len(v.Top) < 6 {
			v.Top = append(v.Top, f)
		}
	}
	if !s.Scan.Started.IsZero() && !s.Scan.Finished.IsZero() {
		v.Duration = s.Scan.Finished.Sub(s.Scan.Started).Round(time.Second).String()
	}
	score := s.Score
	if score < 0 {
		score = 0
	}
	circ := 2 * 3.14159 * 52
	v.GaugeDash = fmt.Sprintf("%.1f %.1f", circ*float64(score)/100, circ)
	switch {
	case score >= 80:
		v.GaugeColor = "#16a34a"
	case score >= 60:
		v.GaugeColor = "#d97706"
	default:
		v.GaugeColor = "#dc2626"
	}
	v.Summary = summary(s, v)
	b, _ := json.Marshal(TopologyData(s.Devices, s.Links, s.Findings))
	v.MapJSON = template.JS(b)
	v.MapJS = template.JS(ui.Read("map.js"))
	v.Talkers = s.Flows.TopTalkers
	if len(v.Talkers) > 10 {
		v.Talkers = v.Talkers[:10]
	}
	v.Apps = s.Flows.TopApps
	if len(v.Apps) > 10 {
		v.Apps = v.Apps[:10]
	}
	return tmpl.Execute(w, v)
}

var typeLabels = map[string]string{"voip-phone": "VoIP phone", "nas": "NAS", "ups": "UPS", "iot": "IoT",
	"access-point": "Access point"}

// TypeLabel is the display name for a device type.
func TypeLabel(s string) string {
	if l, ok := typeLabels[s]; ok {
		return l
	}
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, "-", " ")
	return strings.ToUpper(s[:1]) + s[1:]
}

var vendorNoise = regexp.MustCompile(`(?i)[,.]?\s*\b(co\.?,?\s*ltd|corporation|corp|incorporated|inc|ltd|llc|gmbh|limited|technologies|technology|communications?|electronics|systems|network|networks|international|company|mobile)\b\.?`)

// ShortVendor trims registry boilerplate: "Yealink(Xiamen) Network
// Technology Co.,Ltd." -> "Yealink".
func ShortVendor(v string) string {
	if i := strings.IndexAny(v, "(（"); i > 0 {
		v = v[:i]
	}
	for i := 0; i < 3; i++ {
		v = vendorNoise.ReplaceAllString(v, "")
	}
	return strings.Trim(strings.TrimSpace(v), ",.")
}

// inlineCode escapes s and renders `backtick` spans as <code>.
func inlineCode(s string) template.HTML {
	parts := strings.Split(s, "`")
	var b strings.Builder
	for i, p := range parts {
		e := template.HTMLEscapeString(p)
		if i%2 == 1 && i < len(parts)-1 {
			b.WriteString("<code>" + e + "</code>")
		} else {
			if i%2 == 1 {
				b.WriteString("`")
			}
			b.WriteString(e)
		}
	}
	return template.HTML(b.String())
}

func summary(s *model.Snapshot, v view) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("OctoLAN identified %d devices (%d responding during the assessment) across %d subnet(s)", len(s.Devices), v.Alive, len(s.Subnets)))
	if v.Infra > 0 {
		parts[0] += fmt.Sprintf(", including %d network infrastructure devices", v.Infra)
	}
	parts[0] += "."
	crit, high := v.SevCount["critical"], v.SevCount["high"]
	switch {
	case crit > 0:
		parts = append(parts, fmt.Sprintf("%d critical and %d high-severity issues need immediate attention.", crit, high))
	case high > 0:
		parts = append(parts, fmt.Sprintf("No critical issues were found, but %d high-severity issues should be remediated promptly.", high))
	default:
		parts = append(parts, "No critical or high-severity issues were found.")
	}
	if v.EOL > 0 {
		parts = append(parts, fmt.Sprintf("%d device(s) run software past end of support.", v.EOL))
	}
	return strings.Join(parts, " ")
}

// HumanBytes formats a byte count (1.5 GiB).
func HumanBytes(b uint64) string { return humanBytes(b) }

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ---- CSV ----

// DevicesCSV writes the inventory.
func DevicesCSV(w *csv.Writer, devs []*model.Device) error {
	_ = w.Write([]string{"Name", "IP addresses", "MAC", "Vendor", "Type", "OS", "OS confidence", "EOL", "Model", "Serial", "Firmware", "Open ports", "SNMP", "Domain", "Location", "First seen", "Last seen", "Discovered by"})
	for _, d := range devs {
		var ports []string
		for _, p := range d.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Service))
		}
		snmp := ""
		if d.SNMP != nil {
			snmp = d.SNMP.Version
		}
		os := d.OS.Name
		if os == "" {
			os = d.OS.Family
		}
		_ = w.Write([]string{Label(d), strings.Join(d.IPs, " "), d.MAC, d.Vendor, string(d.Type), os,
			fmt.Sprint(d.OS.Confidence), fmt.Sprint(d.OS.EOL), d.Model, d.Serial, d.Firmware,
			strings.Join(ports, " "), snmp, d.Domain, d.Location,
			d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339), strings.Join(d.Sources, " ")})
	}
	w.Flush()
	return w.Error()
}

// FindingsCSV writes one row per finding/device pair.
func FindingsCSV(w *csv.Writer, finds []model.Finding, devs []*model.Device) error {
	byID := map[string]*model.Device{}
	for _, d := range devs {
		byID[d.ID] = d
	}
	_ = w.Write([]string{"Severity", "Category", "Finding", "Device", "IP", "Detail", "Remediation"})
	for _, f := range finds {
		if len(f.Devices) == 0 {
			_ = w.Write([]string{string(f.Severity), f.Category, f.Title, "", "", f.Detail, f.Remediation})
			continue
		}
		for _, id := range f.Devices {
			name, ip := id, ""
			if d := byID[id]; d != nil {
				name = Label(d)
				if len(d.IPs) > 0 {
					ip = d.IPs[0]
				}
			}
			_ = w.Write([]string{string(f.Severity), f.Category, f.Title, name, ip, f.Detail, f.Remediation})
		}
	}
	w.Flush()
	return w.Error()
}
