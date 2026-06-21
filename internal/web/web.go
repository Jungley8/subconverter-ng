// Package web serves the embedded single-page web UI that helps users build a
// /sub?... subscription URL for their Clash client. All assets are baked into
// the binary via go:embed, so there is no separate service or build step.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var assets embed.FS

// Handler returns an http.Handler that serves the embedded assets, with
// assets/index.html served at "/".
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		// assets is embedded at build time; this can only fail if the embed
		// directive is broken, which would be caught at compile/test time.
		panic(err)
	}
	return http.FileServerFS(sub)
}
