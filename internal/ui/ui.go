// Package ui embeds the dashboard's static files so the binary is fully
// self-contained (no CDN; customer sites are often offline or filtered).
package ui

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// FS is the static web root.
func FS() fs.FS {
	sub, _ := fs.Sub(files, "static")
	return sub
}

// Read returns one embedded file (used by the HTML report).
func Read(name string) string {
	b, _ := files.ReadFile("static/" + name)
	return string(b)
}
