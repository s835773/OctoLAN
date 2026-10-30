package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/s835773/OctoLAN/internal/engine"
	"github.com/s835773/OctoLAN/internal/store"
	"github.com/s835773/OctoLAN/internal/vault"
)

var stdin = bufio.NewReader(os.Stdin)

// readSecret reads a line without echo when attached to a terminal.
func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := stdin.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func readLine(prompt, def string) string {
	if def != "" {
		prompt += " [" + def + "]"
	}
	fmt.Fprint(os.Stderr, prompt+": ")
	line, _ := stdin.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

const vaultUsage = `Usage: octolan vault <command> -site "Customer name"

  init      create the site's vault
  add       add a credential (prompts; secrets are not echoed)
  list      list credentials (never shows secrets)
  rm ID     delete a credential
  passwd    change the vault passphrase

The vault is ~/OctoLAN/<site>/credentials.octovault, encrypted with
XChaCha20-Poly1305 under an Argon2id-derived key. Use it in a scan with
"octolan scan -site ... -vault" or unlock it in the dashboard.`

func cmdVault(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-h") {
		fmt.Println(vaultUsage)
		return nil
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("vault", flag.ExitOnError)
	site := fs.String("site", "", "customer / site name")
	data := fs.String("data", defaultDataDir(), "where sessions and vaults are stored")
	_ = fs.Parse(flagsFirst(args, map[string]bool{"-site": true, "--site": true, "-data": true, "--data": true}))
	if strings.TrimSpace(*site) == "" {
		return errors.New("-site is required (each customer has their own vault)")
	}
	st := store.New()
	st.SetSite(*site)
	e := engine.New(st, Version, *data)
	path := e.VaultPath()

	if sub == "init" {
		p1, err := readSecret(fmt.Sprintf("New vault passphrase (min %d chars): ", vault.MinPassphrase))
		if err != nil {
			return err
		}
		p2, _ := readSecret("Confirm passphrase: ")
		if p1 != p2 {
			return errors.New("passphrases don't match")
		}
		if err := e.VaultCreate(p1); err != nil {
			return err
		}
		fmt.Println("Vault created:", path)
		return nil
	}
	if !vault.Exists(path) {
		return fmt.Errorf("no vault for %q yet: run `octolan vault init -site %q`", *site, *site)
	}
	pass, err := readSecret("Vault passphrase: ")
	if err != nil {
		return err
	}
	v, err := vault.Open(path, pass)
	if err != nil {
		return err
	}
	defer v.Lock()

	switch sub {
	case "list", "ls":
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tTYPE\tACCOUNT\tSCOPE")
		for _, c := range v.Views() {
			acct := c.Username
			if c.Domain != "" {
				acct = c.Domain + `\` + c.Username
			}
			if c.Type == vault.TypeSNMP && c.SNMPVersion != "v3" {
				acct = "community ••••"
			}
			scope := strings.Join(c.Scope, ",")
			if scope == "" {
				scope = "(scan targets)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.ID, c.Name, c.Type, acct, scope)
		}
		tw.Flush()
		if cv := v.ConfigViews(); len(cv) > 0 {
			fmt.Printf("\n%d config backup(s) stored.\n", len(cv))
		}
	case "add":
		var c vault.Cred
		switch strings.ToLower(readLine("Type (windows/ssh/snmp)", "windows")) {
		case "windows", "win":
			c.Type = vault.TypeWindows
			c.Domain = readLine("Domain (blank for a local account)", "")
			c.Username = readLine("Username", "")
			c.Password, _ = readSecret("Password: ")
		case "ssh":
			c.Type = vault.TypeSSH
			c.Username = readLine("Username", "")
			c.Password, _ = readSecret("Password (blank if using a key): ")
			if kp := readLine("Private key file (optional)", ""); kp != "" {
				b, err := os.ReadFile(kp)
				if err != nil {
					return err
				}
				c.PrivateKey = string(b)
				c.KeyPassphrase, _ = readSecret("Key passphrase (blank if none): ")
			}
			c.Enable, _ = readSecret("Enable secret (Cisco, blank if none): ")
		case "snmp":
			c.Type = vault.TypeSNMP
			c.SNMPVersion = readLine("Version (v2c/v3)", "v2c")
			if c.SNMPVersion == "v3" {
				c.Username = readLine("v3 user", "")
				c.AuthProto = readLine("Auth protocol (SHA/SHA256/SHA512/MD5)", "SHA")
				c.AuthPass, _ = readSecret("Auth password: ")
				c.PrivProto = readLine("Privacy protocol (AES/AES256/DES)", "AES")
				c.PrivPass, _ = readSecret("Privacy password: ")
			} else {
				c.Community, _ = readSecret("Community: ")
			}
		default:
			return errors.New("type must be windows, ssh or snmp")
		}
		c.Name = readLine("Name", "")
		if sc := readLine("Scope (CIDRs/IPs, blank = scan targets)", ""); sc != "" {
			c.Scope = []string{sc}
		}
		view, err := v.Put(c)
		if err != nil {
			return err
		}
		fmt.Printf("Saved %q (%s).\n", view.Name, view.ID)
	case "rm", "delete":
		if fs.NArg() != 1 {
			return errors.New("usage: octolan vault rm -site NAME ID")
		}
		if err := v.Delete(fs.Arg(0)); err != nil {
			return err
		}
		fmt.Println("Deleted.")
	case "passwd":
		p1, _ := readSecret("New passphrase: ")
		p2, _ := readSecret("Confirm: ")
		if p1 != p2 {
			return errors.New("passphrases don't match")
		}
		if err := v.ChangePassphrase(p1); err != nil {
			return err
		}
		fmt.Println("Passphrase changed.")
	default:
		fmt.Println(vaultUsage)
	}
	return nil
}
