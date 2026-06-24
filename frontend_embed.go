//go:build windows && !gui

package main

import (
	"embed"
	"io/fs"
)

// frontendDist embeds the built React console so the headless service can serve it over HTTP.
// (The Wails GUI build embeds the same directory via main_gui.go under the `gui` tag.)
//
//go:embed all:cmd/gui/dist
var frontendDist embed.FS

// frontendFS returns the embedded frontend rooted at the dist directory.
func frontendFS() (fs.FS, error) {
	return fs.Sub(frontendDist, "cmd/gui/dist")
}
