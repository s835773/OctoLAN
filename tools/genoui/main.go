// Command genoui converts Wireshark's "manuf" file into the compact,
// gzipped vendor table embedded by internal/oui.
//
//	curl -fsSLo manuf https://www.wireshark.org/download/automated/data/manuf
//	go run ./tools/genoui manuf internal/oui/oui.txt.gz
package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: genoui <manuf> <out.txt.gz>")
		os.Exit(2)
	}
	in, err := os.Open(os.Args[1])
	check(err)
	defer in.Close()
	out, err := os.Create(os.Args[2])
	check(err)
	defer out.Close()
	gz, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	defer gz.Close()

	n := 0
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 2 {
			continue
		}
		prefix := strings.TrimSpace(cols[0])
		name := strings.TrimSpace(cols[len(cols)-1])
		if name == "" {
			name = strings.TrimSpace(cols[1])
		}
		bits := 24
		if i := strings.IndexByte(prefix, '/'); i >= 0 {
			fmt.Sscanf(prefix[i+1:], "%d", &bits)
			prefix = prefix[:i]
		}
		hex := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(prefix))
		if len(hex) < bits/4 {
			continue
		}
		fmt.Fprintf(gz, "%s/%d\t%s\n", hex[:bits/4], bits, name)
		n++
	}
	check(sc.Err())
	fmt.Fprintf(os.Stderr, "wrote %d prefixes\n", n)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
