// Package web serves the OctoLAN dashboard and its JSON API.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/s835773/OctoLAN/internal/discovery"
	"github.com/s835773/OctoLAN/internal/engine"
	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/report"
	"github.com/s835773/OctoLAN/internal/ui"
)

// Server is the HTTP front end.
type Server struct {
	E     *engine.Engine
	Token string // required for non-loopback listeners
	srv   *http.Server
}

// NewToken returns a random access token.
func NewToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("GET /api/devices", s.devices)
	mux.HandleFunc("GET /api/devices/{id}", s.device)
	mux.HandleFunc("PATCH /api/devices/{id}", s.patchDevice)
	mux.HandleFunc("GET /api/topology", s.topology)
	mux.HandleFunc("GET /api/findings", s.findings)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/flows", s.flows)
	mux.HandleFunc("GET /api/storm", s.storm)
	mux.HandleFunc("GET /api/l2", s.l2)
	mux.HandleFunc("POST /api/scan", s.startScan)
	mux.HandleFunc("POST /api/scan/stop", s.stopScan)
	mux.HandleFunc("POST /api/analyze", s.analyze)
	mux.HandleFunc("POST /api/monitor", s.monitor)
	mux.HandleFunc("POST /api/netflow", s.netflow)
	mux.HandleFunc("POST /api/site", s.site)
	mux.HandleFunc("GET /api/stream", s.stream)
	mux.HandleFunc("GET /api/export/report.html", s.exportReport)
	mux.HandleFunc("GET /api/export/session.json", s.exportJSON)
	mux.HandleFunc("GET /api/export/devices.csv", s.exportCSV)
	mux.HandleFunc("GET /api/export/findings.csv", s.exportFindingsCSV)
	static := http.FileServerFS(ui.FS())
	mux.Handle("GET /", static)
	return s.auth(securityHeaders(mux))
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.ServeHTTP(w, r)
	})
}

// auth enforces the token (query ?token= once, then a cookie) and blocks
// cross-site requests to state-changing endpoints.
func (s *Server) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			// Same-origin only for writes (defends against CSRF from a
			// malicious page the tech browses while OctoLAN runs).
			if o := r.Header.Get("Origin"); o != "" && !strings.HasSuffix(o, "://"+r.Host) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		if s.Token == "" {
			h.ServeHTTP(w, r)
			return
		}
		if q := r.URL.Query().Get("token"); q != "" && subtle.ConstantTimeCompare([]byte(q), []byte(s.Token)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "octolan", Value: s.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			h.ServeHTTP(w, r)
			return
		}
		if c, err := r.Cookie("octolan"); err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.Token)) == 1 {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "OctoLAN: open the URL printed in the terminal (it includes the access token).")
	})
}

// ListenAndServe starts serving on addr until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, ln net.Listener) error {
	s.srv = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(sh)
	}()
	err := s.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// ---- read endpoints ----

type stateResp struct {
	Version   string             `json:"version"`
	Site      string             `json:"site"`
	Caps      model.Capabilities `json:"capabilities"`
	Scan      model.ScanStatus   `json:"scan"`
	Score     int                `json:"score"`
	Grade     string             `json:"grade"`
	Counts    map[string]int     `json:"counts"`
	Types     map[string]int     `json:"types"`
	Severity  map[string]int     `json:"severity"`
	Subnets   []model.Subnet     `json:"subnets"`
	Passive   any                `json:"passive"`
	Storm     stormBrief         `json:"storm"`
	NetFlow   flowBrief          `json:"netflow"`
	DHCP      []model.DHCPServer `json:"dhcp"`
	VLANCount int                `json:"vlanCount"`
	Defaults  scanDefaults       `json:"defaults"`
}

type stormBrief struct {
	State   string `json:"state"`
	Running bool   `json:"running"`
	Error   string `json:"error,omitempty"`
	PPS     int    `json:"pps"`
	Bcast   int    `json:"bcast"`
}

type flowBrief struct {
	Listening bool   `json:"listening"`
	Addr      string `json:"addr,omitempty"`
	Exporters int    `json:"exporters"`
	Flows     uint64 `json:"flows"`
}

type scanDefaults struct {
	Targets     string   `json:"targets"`
	Communities []string `json:"communities"`
	Ports       []int    `json:"ports"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	st := s.E.St
	devs := st.Devices()
	finds, score, grade := st.Findings()
	resp := stateResp{
		Version: s.E.Version, Site: st.Site(), Caps: st.Caps(), Scan: st.Scan(), Score: score, Grade: grade,
		Counts: map[string]int{}, Types: map[string]int{}, Severity: map[string]int{},
		Subnets: st.Subnets(), Passive: s.E.PassiveStats(), DHCP: st.DHCPServers(), VLANCount: len(st.VLANs()),
	}
	for _, d := range devs {
		resp.Counts["devices"]++
		if d.Alive {
			resp.Counts["alive"]++
		}
		resp.Types[string(d.Type)]++
		switch d.Type {
		case model.TypeRouter, model.TypeSwitch, model.TypeFirewall, model.TypeAccessPoint:
			resp.Counts["infrastructure"]++
		}
		if d.SNMP != nil {
			resp.Counts["snmp"]++
		}
		if d.OS.EOL {
			resp.Counts["eol"]++
		}
	}
	for _, f := range finds {
		resp.Severity[string(f.Severity)]++
	}
	resp.Counts["findings"] = len(finds)
	resp.Counts["links"] = len(st.Links())
	sb := s.E.StormStatus()
	resp.Storm = stormBrief{State: sb.State, Running: sb.Running, Error: sb.Error, PPS: sb.Current.Total, Bcast: sb.Current.Broadcast + sb.Current.Multicast}
	fs := s.E.FlowSummary()
	resp.NetFlow = flowBrief{Listening: fs.Listening, Addr: fs.ListenAddr, Exporters: len(fs.Exporters), Flows: fs.TotalFlows}
	if d, ok := defaultTarget(resp.Caps); ok {
		resp.Defaults.Targets = d
	}
	resp.Defaults.Communities = discovery.DefaultCommunities
	resp.Defaults.Ports = discovery.DefaultPorts
	writeJSON(w, resp)
}

func defaultTarget(c model.Capabilities) (string, bool) {
	for _, i := range c.Interfaces {
		if i.Name == c.DefaultIface && len(i.Addrs) > 0 {
			_, n, err := net.ParseCIDR(i.Addrs[0])
			if err != nil {
				return "", false
			}
			ones, _ := n.Mask.Size()
			if ones < 22 {
				ip, _, _ := net.ParseCIDR(i.Addrs[0])
				n = &net.IPNet{IP: ip.Mask(net.CIDRMask(22, 32)), Mask: net.CIDRMask(22, 32)}
			}
			return n.String(), true
		}
	}
	return "", false
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.E.St.Devices())
}

func (s *Server) device(w http.ResponseWriter, r *http.Request) {
	d := s.E.St.Get(r.PathValue("id"))
	if d == nil {
		httpErr(w, http.StatusNotFound, errors.New("no such device"))
		return
	}
	writeJSON(w, d)
}

// patchDevice lets the tech correct type/name/notes from the drawer.
func (s *Server) patchDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type     *string `json:"type"`
		Hostname *string `json:"hostname"`
		Notes    *string `json:"notes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	ok := s.E.St.Update(r.PathValue("id"), func(d *model.Device) {
		if body.Type != nil {
			d.Type = model.DeviceType(*body.Type)
			d.OS.Evidence = append(d.OS.Evidence, "type set manually")
		}
		if body.Hostname != nil {
			d.Hostname = strings.TrimSpace(*body.Hostname)
		}
		if body.Notes != nil {
			d.Notes = *body.Notes
		}
	})
	if !ok {
		httpErr(w, http.StatusNotFound, errors.New("no such device"))
		return
	}
	writeJSON(w, s.E.St.Get(r.PathValue("id")))
}

func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	finds, _, _ := s.E.St.Findings()
	writeJSON(w, report.TopologyData(s.E.St.Devices(), s.E.St.Links(), finds))
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	f, score, grade := s.E.St.Findings()
	writeJSON(w, map[string]any{"findings": f, "score": score, "grade": grade})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 500
	}
	writeJSON(w, s.E.St.Events(n))
}

func (s *Server) flows(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.E.FlowSummary()) }
func (s *Server) storm(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.E.StormStatus()) }

type l2Neighbor struct {
	Device string `json:"device"`
	DevID  string `json:"deviceId"`
	model.Neighbor
}

func (s *Server) l2(w http.ResponseWriter, r *http.Request) {
	var nbrs []l2Neighbor
	for _, d := range s.E.St.Devices() {
		for _, n := range d.Neighbors {
			nbrs = append(nbrs, l2Neighbor{Device: report.Label(d), DevID: d.ID, Neighbor: n})
		}
	}
	writeJSON(w, map[string]any{
		"vlans": s.E.St.VLANs(), "dhcp": s.E.St.DHCPServers(), "neighbors": nbrs,
		"stp": s.E.StormStatus().STP, "duplicates": s.E.St.DuplicateIPs(),
	})
}

// ---- actions ----

type scanReq struct {
	Site           string             `json:"site"`
	Interface      string             `json:"interface"`
	Targets        string             `json:"targets"`
	Communities    string             `json:"communities"`
	SNMPv3         []model.SNMPv3Cred `json:"snmpv3"`
	Ports          string             `json:"ports"`
	PassiveSeconds int                `json:"passiveSeconds"`
	ZeroFootprint  bool               `json:"zeroFootprint"`
	SkipSNMP       bool               `json:"skipSnmp"`
	Rate           int                `json:"rate"`
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req scanReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	cfg := model.ScanConfig{
		Site: strings.TrimSpace(req.Site), Interface: req.Interface, Ports: req.Ports,
		PassiveSeconds: req.PassiveSeconds, ZeroFootprint: req.ZeroFootprint, SkipSNMP: req.SkipSNMP, Rate: req.Rate,
	}
	if t := strings.TrimSpace(req.Targets); t != "" {
		cfg.Targets = []string{t}
	}
	for _, c := range strings.FieldsFunc(req.Communities, func(r rune) bool { return r == ',' || r == '\n' }) {
		if c = strings.TrimSpace(c); c != "" {
			cfg.Communities = append(cfg.Communities, c)
		}
	}
	for _, v3 := range req.SNMPv3 {
		if strings.TrimSpace(v3.User) != "" {
			cfg.SNMPv3 = append(cfg.SNMPv3, v3)
		}
	}
	if cfg.ZeroFootprint && cfg.PassiveSeconds <= 0 {
		cfg.PassiveSeconds = 120
	}
	if err := s.E.StartScan(cfg); err != nil {
		httpErr(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) stopScan(w http.ResponseWriter, r *http.Request) {
	go s.E.StopScan()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) analyze(w http.ResponseWriter, r *http.Request) {
	s.E.Analyze()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) monitor(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Interface string `json:"interface"`
		Enable    bool   `json:"enable"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	if !body.Enable {
		s.E.StopMonitoring()
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	if err := s.E.StartMonitoring(body.Interface); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) netflow(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Addr   string `json:"addr"`
		Enable bool   `json:"enable"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	if !body.Enable {
		s.E.StopNetFlow()
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	if err := s.E.StartNetFlow(body.Addr); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) site(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	s.E.St.SetSite(strings.TrimSpace(body.Name))
	writeJSON(w, map[string]bool{"ok": true})
}

// stream is a Server-Sent Events feed of store changes.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, unsub := s.E.St.Subscribe()
	defer unsub()
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case m, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(m)
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
}

// ---- exports ----

func (s *Server) filename(ext string) string {
	site := strings.Map(func(r rune) rune {
		if r == ' ' {
			return '-'
		}
		if r < 32 || strings.ContainsRune(`/\:*?"<>|`, r) {
			return -1
		}
		return r
	}, s.E.St.Site())
	if site == "" {
		site = "octolan"
	}
	return fmt.Sprintf("%s-%s.%s", site, time.Now().Format("2006-01-02"), ext)
}

func (s *Server) exportReport(w http.ResponseWriter, r *http.Request) {
	snap := s.E.St.Snapshot(s.E.Version)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+s.filename("html")+`"`)
	}
	// The report has its own inline script; relax CSP for this response.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
	if err := report.Write(w, &snap); err != nil {
		httpErr(w, http.StatusInternalServerError, err)
	}
}

func (s *Server) exportJSON(w http.ResponseWriter, r *http.Request) {
	snap := s.E.St.Snapshot(s.E.Version)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+s.filename("json")+`"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="`+s.filename("devices.csv")+`"`)
	_ = report.DevicesCSV(csv.NewWriter(w), s.E.St.Devices())
}

func (s *Server) exportFindingsCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="`+s.filename("findings.csv")+`"`)
	f, _, _ := s.E.St.Findings()
	_ = report.FindingsCSV(csv.NewWriter(w), f, s.E.St.Devices())
}
