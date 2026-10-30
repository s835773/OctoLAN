// Command oculan is a portable network discovery and assessment tool for
// MSP technicians: run it on a laptop at a customer site to map the
// network, inventory devices and score its security posture.
//
//	oculan                      start the live dashboard in your browser
//	oculan scan [flags]         run a full assessment from the terminal
//	oculan report <session>     regenerate a report from a saved session
//	oculan storm                live broadcast-storm / STP meter
//	oculan netflow              live NetFlow/IPFIX top talkers
//	oculan passive              listen-only discovery (sends nothing)
//	oculan interfaces           show interfaces and what this host can do
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/s835773/OcuLAN/internal/engine"
	"github.com/s835773/OcuLAN/internal/model"
	"github.com/s835773/OcuLAN/internal/report"
	"github.com/s835773/OcuLAN/internal/store"
	"github.com/s835773/OcuLAN/internal/web"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

const banner = `   ____            _      ___    _  __
  / __ \_______ __/ /    / _ |  / |/ /
 / /_/ / __/ // / /__  / __ | /    /
 \____/\__/\_,_/____/ /_/ |_|/_/|_/   network assessment %s
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve", "dashboard", "ui":
		err = cmdServe(args)
	case "scan":
		err = cmdScan(args)
	case "report":
		err = cmdReport(args)
	case "storm":
		err = cmdStorm(args)
	case "netflow":
		err = cmdNetflow(args)
	case "passive":
		err = cmdPassive(args)
	case "interfaces", "ifaces", "caps":
		err = cmdInterfaces()
	case "version", "--version":
		fmt.Println("oculan", Version, runtime.GOOS+"/"+runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(banner, Version)
	fmt.Print(`
Usage:
  oculan [serve]        Live dashboard (opens your browser)
  oculan scan           Full assessment from the terminal; writes report.html
  oculan report FILE    Rebuild the HTML report from a saved session JSON
  oculan storm          Live broadcast/multicast PPS meter and STP watch
  oculan netflow        NetFlow v5/v9/IPFIX collector with live top talkers
  oculan passive        Listen-only discovery: never transmits a packet
  oculan interfaces     List interfaces and this host's capabilities
  oculan version

Run "oculan <command> -h" for flags. Raw-packet features (ARP sweep,
passive capture, Storm Guard, SYN-ACK fingerprinting) need sudo on
Linux/macOS, or Npcap on Windows; everything else works without them.
`)
}

func defaultDataDir() string {
	if d, err := os.UserHomeDir(); err == nil {
		return filepath.Join(d, "OcuLAN")
	}
	return "oculan-data"
}

func signalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// ---- serve ----

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8484", "address for the dashboard (use 0.0.0.0:8484 to share with teammates; a token is then required)")
	iface := fs.String("iface", "", "interface to monitor (default: the one with the default route)")
	site := fs.String("site", "", "customer / site name")
	noBrowser := fs.Bool("no-browser", false, "don't open a browser")
	nf := fs.String("netflow", "", "also start the NetFlow collector on this address (e.g. :2055)")
	data := fs.String("data", defaultDataDir(), "where sessions are saved")
	load := fs.String("load", "", "reopen a saved session JSON")
	autoscan := fs.Bool("scan", false, "start an assessment immediately with default settings")
	_ = fs.Parse(args)

	fmt.Printf(banner, Version)
	st := store.New()
	st.SetSite(*site)
	e := engine.New(st, Version, *data)
	if *load != "" {
		snap, err := store.LoadSnapshot(*load)
		if err != nil {
			return err
		}
		st.Restore(snap)
		if *site != "" {
			st.SetSite(*site)
		}
		fmt.Printf("Loaded %d devices from %s\n", len(snap.Devices), *load)
	}
	caps := e.DetectCaps()
	printCaps(caps)
	if err := e.StartMonitoring(*iface); err != nil {
		fmt.Println("  monitoring:", err)
	}
	if *nf != "" {
		if err := e.StartNetFlow(*nf); err != nil {
			fmt.Println("  netflow:", err)
		}
	}

	host, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("bad -listen: %w", err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("can't listen on %s: %w (is another OcuLAN running? try -listen 127.0.0.1:0)", *listen, err)
	}
	srv := &web.Server{E: e}
	loopback := false
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() || host == "localhost" {
		loopback = true
	}
	if !loopback {
		srv.Token = web.NewToken()
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/", actualPort)
	if srv.Token != "" {
		url += "?token=" + srv.Token
		fmt.Println("\n  Dashboard is reachable from the network. Share these links only with your team:")
		for _, a := range engine.LocalAddrs() {
			fmt.Printf("    http://%s:%d/?token=%s\n", a, actualPort, srv.Token)
		}
	}
	_ = port
	fmt.Printf("\n  ➜  Dashboard: %s\n  Press Ctrl+C to stop (the session is saved automatically).\n\n", url)

	ctx, cancel := signalCtx()
	defer cancel()
	if !*noBrowser {
		go func() {
			time.Sleep(400 * time.Millisecond)
			openBrowser(url)
		}()
	}
	if *autoscan {
		_ = e.StartScan(model.ScanConfig{Site: *site, Interface: *iface, PassiveSeconds: 60})
	}
	// Periodic autosave while devices exist.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if len(st.Devices()) > 0 && !e.Running() {
					_, _ = e.AutoSave()
				}
			}
		}
	}()
	err = srv.ListenAndServe(ctx, ln)
	fmt.Println("\nShutting down…")
	e.StopScan()
	if len(st.Devices()) > 0 {
		e.Analyze()
		if p, serr := e.AutoSave(); serr == nil {
			fmt.Println("Session saved to", p)
		}
	}
	e.StopNetFlow()
	e.StopMonitoring()
	return err
}

func openBrowser(url string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", url)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	_ = c.Start()
}

func printCaps(c model.Capabilities) {
	fmt.Printf("  Host %s (%s/%s)\n", c.Hostname, c.OS, c.Arch)
	for _, i := range c.Interfaces {
		mark := " "
		if i.Name == c.DefaultIface {
			mark = "*"
		}
		gw := ""
		if i.Gateway != "" {
			gw = "  gw " + i.Gateway
		}
		fmt.Printf("  %s %-12s %-18s %s%s\n", mark, i.Name, strings.Join(i.Addrs, ","), i.MAC, gw)
	}
	if c.RawCapture {
		fmt.Println("  ✓ raw capture: ARP sweep, passive discovery, Storm Guard and SYN-ACK fingerprinting enabled")
	} else {
		fmt.Println("  ! raw capture unavailable:", c.CaptureNote)
		fmt.Println("    (discovery still works via ping, OS ARP cache, TCP, SNMP, SMB, DNS/NetBIOS/mDNS)")
	}
	fmt.Println("  ICMP mode:", c.ICMPMode)
}

// ---- scan ----

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var targets, comms, v3 listFlag
	fs.Var(&targets, "t", "target CIDR/range/IP (repeatable; default: local subnet)")
	fs.Var(&comms, "c", "SNMP v1/v2c community (repeatable; default: public,private)")
	fs.Var(&v3, "v3", "SNMPv3 credential user:SHA:authpass:AES:privpass (repeatable)")
	iface := fs.String("iface", "", "interface (default: the one with the default route)")
	site := fs.String("site", "", "customer / site name")
	ports := fs.String("ports", "default", `TCP ports: "default", "top" (1-1024 + defaults), "none", or a list like "22,80,8000-8100"`)
	passiveSec := fs.Int("passive", 60, "total seconds to keep listening passively (DHCP, LLDP, STP, mDNS…)")
	zero := fs.Bool("zero-footprint", false, "passive only: never transmit a packet")
	noSNMP := fs.Bool("no-snmp", false, "skip SNMP polling")
	rate := fs.Int("rate", 400, "packets per second for ARP/ICMP sweeps")
	out := fs.String("out", "", "output directory (default: ~/OcuLAN/<site>)")
	nf := fs.String("netflow", "", "also collect NetFlow on this address during the scan (e.g. :2055)")
	_ = fs.Parse(args)

	fmt.Printf(banner, Version)
	st := store.New()
	st.SetSite(*site)
	data := defaultDataDir()
	if *out != "" {
		data = *out
	}
	e := engine.New(st, Version, data)
	printCaps(e.DetectCaps())
	if *nf != "" {
		if err := e.StartNetFlow(*nf); err != nil {
			fmt.Println("  netflow:", err)
		}
	}

	cfg := model.ScanConfig{Site: *site, Interface: *iface, Targets: targets, Communities: comms,
		Ports: *ports, PassiveSeconds: *passiveSec, ZeroFootprint: *zero, SkipSNMP: *noSNMP, Rate: *rate}
	for _, s := range v3 {
		p := strings.Split(s, ":")
		c := model.SNMPv3Cred{User: p[0]}
		if len(p) >= 3 {
			c.AuthProto, c.AuthPass = p[1], p[2]
		}
		if len(p) >= 5 {
			c.PrivProto, c.PrivPass = p[3], p[4]
		}
		cfg.SNMPv3 = append(cfg.SNMPv3, c)
	}

	ctx, cancel := signalCtx()
	defer cancel()
	// Live progress line.
	msgs, unsub := st.Subscribe()
	defer unsub()
	go func() {
		last := ""
		for m := range msgs {
			switch m.Type {
			case "scan":
				s, _ := m.Data.(model.ScanStatus)
				line := fmt.Sprintf("[%3.0f%%] %-18s %s", s.Progress*100, s.Phase, s.Message)
				if line != last {
					fmt.Printf("\r\033[K%s", truncate(line, 110))
					last = line
				}
			case "event":
				ev, _ := m.Data.(model.Event)
				if ev.Severity == model.SevHigh || ev.Severity == model.SevCritical {
					fmt.Printf("\r\033[K  ⚠ %s\n", ev.Message)
				}
			}
		}
	}()
	err := e.RunScan(ctx, cfg)
	fmt.Print("\r\033[K")
	e.StopMonitoring()
	e.StopNetFlow()
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	devs := st.Devices()
	printDevices(devs)
	finds, score, grade := st.Findings()
	fmt.Printf("\nPosture score: %d/100 (grade %s), %d findings\n", score, grade, len(finds))
	for _, f := range finds {
		if f.Severity == model.SevInfo {
			continue
		}
		n := ""
		if len(f.Devices) > 0 {
			n = fmt.Sprintf(" (%d devices)", len(f.Devices))
		}
		fmt.Printf("  %-9s %s%s\n", strings.ToUpper(string(f.Severity)), f.Title, n)
	}

	dir := e.SessionDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	stamp := time.Now().Format("20060102-150405")
	rp := filepath.Join(dir, "report-"+stamp+".html")
	f, err := os.Create(rp)
	if err != nil {
		return err
	}
	snap := st.Snapshot(Version)
	if err := report.Write(f, &snap); err != nil {
		f.Close()
		return err
	}
	f.Close()
	jp := filepath.Join(dir, "session-"+stamp+".json")
	if err := st.Save(jp, Version); err != nil {
		return err
	}
	fmt.Printf("\nReport:  %s\nSession: %s\n", rp, jp)
	return nil
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func printDevices(devs []*model.Device) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nIP\tNAME\tMAC\tVENDOR\tTYPE\tOS\tPORTS")
	for _, d := range devs {
		ip := ""
		if len(d.IPs) > 0 {
			ip = d.IPs[0]
		}
		os := d.OS.Name
		if os == "" {
			os = d.OS.Family
		}
		var ps []string
		for _, p := range d.Ports {
			ps = append(ps, fmt.Sprint(p.Port))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ip, truncate(report.Label(d), 28), d.MAC,
			truncate(d.Vendor, 22), d.Type, truncate(os, 30), truncate(strings.Join(ps, ","), 30))
	}
	tw.Flush()
}

// ---- report ----

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	out := fs.String("o", "", "output HTML file (default: next to the session)")
	_ = fs.Parse(flagsFirst(args, map[string]bool{"-o": true, "--o": true}))
	if fs.NArg() != 1 {
		return errors.New("usage: oculan report [-o out.html] session.json")
	}
	snap, err := store.LoadSnapshot(fs.Arg(0))
	if err != nil {
		return err
	}
	path := *out
	if path == "" {
		path = strings.TrimSuffix(fs.Arg(0), filepath.Ext(fs.Arg(0))) + ".html"
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := report.Write(f, snap); err != nil {
		return err
	}
	fmt.Println("Report written to", path)
	return nil
}

// flagsFirst moves positional arguments after flags so "report file -o x"
// works as well as "report -o x file".
func flagsFirst(args []string, takesValue map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if takesValue[a] && !strings.Contains(a, "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

// ---- storm ----

func cmdStorm(args []string) error {
	fs := flag.NewFlagSet("storm", flag.ExitOnError)
	iface := fs.String("iface", "", "interface (default: the one with the default route)")
	warn := fs.Int("warn", 1000, "warning threshold, broadcast+multicast pps")
	crit := fs.Int("crit", 5000, "storm threshold, broadcast+multicast pps")
	_ = fs.Parse(args)
	st := store.New()
	e := engine.New(st, Version, defaultDataDir())
	e.SetStormThresholds(*warn, *crit)
	if err := e.StartMonitoring(*iface); err != nil {
		return err
	}
	defer e.StopMonitoring()
	if s := e.StormStatus(); s.Error != "" {
		return errors.New(s.Error)
	}
	ctx, cancel := signalCtx()
	defer cancel()
	msgs, unsub := st.Subscribe()
	defer unsub()
	fmt.Printf("Storm Guard on %s: warn ≥ %d pps, storm ≥ %d pps. Ctrl+C to stop.\n\n", e.StormStatus().Interface, *warn, *crit)
	fmt.Printf("%-8s %8s %8s %8s %8s %6s %6s  %s\n", "TIME", "TOTAL", "BCAST", "MCAST", "UNICAST", "ARP", "DUPS", "STATE")
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s := e.StormStatus()
			fmt.Printf("\nPeak: %d bcast + %d mcast pps. STP: %s root %s, %d topology changes.\n",
				s.Peak.Broadcast, s.Peak.Multicast, s.STP.Protocol, s.STP.RootBridge, s.STP.TopologyChanges)
			return nil
		case m := <-msgs:
			if m.Type == "event" {
				ev := m.Data.(model.Event)
				fmt.Printf("  » %s\n", ev.Message)
			}
		case <-t.C:
			s := e.StormStatus()
			c := s.Current
			fmt.Printf("%-8s %8d %8d %8d %8d %6d %6d  %s\n", time.Now().Format("15:04:05"), c.Total, c.Broadcast, c.Multicast, c.Unicast, c.ARP, c.Dups, strings.ToUpper(s.State))
		}
	}
}

// ---- netflow ----

func cmdNetflow(args []string) error {
	fs := flag.NewFlagSet("netflow", flag.ExitOnError)
	listen := fs.String("listen", ":2055", "UDP address to receive flows on")
	_ = fs.Parse(args)
	st := store.New()
	e := engine.New(st, Version, defaultDataDir())
	if err := e.StartNetFlow(*listen); err != nil {
		return err
	}
	defer e.StopNetFlow()
	fmt.Printf("NetFlow v5/v9/IPFIX collector on UDP %s. Point exporters at this machine:\n", *listen)
	for _, a := range engine.LocalAddrs() {
		fmt.Printf("  %s\n", a)
	}
	ctx, cancel := signalCtx()
	defer cancel()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s := e.FlowSummary()
			fmt.Printf("\n%s  flows %d  bytes %d  exporters %d\n", time.Now().Format("15:04:05"), s.TotalFlows, s.TotalBytes, len(s.Exporters))
			for i, tk := range s.TopTalkers {
				if i >= 10 {
					break
				}
				fmt.Printf("  %-40s %12d bytes\n", tk.Key, tk.Bytes)
			}
		}
	}
}

// ---- passive ----

func cmdPassive(args []string) error {
	fs := flag.NewFlagSet("passive", flag.ExitOnError)
	iface := fs.String("iface", "", "interface")
	secs := fs.Int("seconds", 0, "stop after N seconds (0 = until Ctrl+C)")
	_ = fs.Parse(args)
	st := store.New()
	e := engine.New(st, Version, defaultDataDir())
	if err := e.StartMonitoring(*iface); err != nil {
		return err
	}
	defer e.StopMonitoring()
	ps := e.PassiveStats()
	fmt.Printf("Passive listening on %s (%s mode). Nothing is transmitted. Ctrl+C to stop.\n", ps.Iface, ps.Mode)
	if ps.Note != "" {
		fmt.Println("  note:", ps.Note)
	}
	ctx, cancel := signalCtx()
	defer cancel()
	if *secs > 0 {
		var c2 context.CancelFunc
		ctx, c2 = context.WithTimeout(ctx, time.Duration(*secs)*time.Second)
		defer c2()
	}
	msgs, unsub := st.Subscribe()
	defer unsub()
	seen := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			e.Analyze()
			printDevices(st.Devices())
			ps := e.PassiveStats()
			keys := make([]string, 0, len(ps.Protocol))
			for k := range ps.Protocol {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			fmt.Printf("\n%d packets heard:", ps.Packets)
			for _, k := range keys {
				fmt.Printf(" %s=%d", k, ps.Protocol[k])
			}
			fmt.Println()
			return nil
		case m := <-msgs:
			switch m.Type {
			case "event":
				fmt.Printf("  » %s\n", m.Data.(model.Event).Message)
			case "devices":
				for _, d := range st.Devices() {
					if !seen[d.ID] {
						seen[d.ID] = true
						ip := ""
						if len(d.IPs) > 0 {
							ip = d.IPs[0]
						}
						fmt.Printf("  + %-15s %-17s %-24s %s\n", ip, d.MAC, truncate(d.Vendor, 24), d.Hostname)
					}
				}
			}
		}
	}
}

func cmdInterfaces() error {
	st := store.New()
	e := engine.New(st, Version, defaultDataDir())
	printCaps(e.DetectCaps())
	return nil
}
