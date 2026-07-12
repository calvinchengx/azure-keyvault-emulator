// Package portal embeds the built Svelte operator portal so the single Go
// binary serves it with no Node runtime. The committed dist/ is baked in at
// build time (go:embed), and CI verifies it matches a fresh build.
package portal

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built portal assets rooted at the dist directory.
func Dist() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}
