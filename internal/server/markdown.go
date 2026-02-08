package server

import (
	"bytes"
	"html/template"

	"github.com/yuin/goldmark"
)

// RenderMarkdown converts markdown text to HTML (safe to inject as template.HTML).
func RenderMarkdown(md string) template.HTML {
	var buf bytes.Buffer
	_ = goldmark.Convert([]byte(md), &buf)
	return template.HTML(buf.String())
}
