// Package logging builds the structured logger used across SecureOps binaries.
//
// SecureOps handles secrets (scanner findings can contain credentials), so
// logging is deliberately structured: values are attributes, never interpolated
// strings, which keeps redaction possible at the handler level. See CLAUDE.md §15.3.
package logging

import (
	"io"
	"log/slog"
)

// Options controls logger construction.
type Options struct {
	Level   slog.Level
	Format  string // "json" or "text"
	Service string
	Version string
}

// New returns a structured logger writing to w.
func New(w io.Writer, opts Options) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{Level: opts.Level}

	var handler slog.Handler
	if opts.Format == "text" {
		handler = slog.NewTextHandler(w, handlerOpts)
	} else {
		handler = slog.NewJSONHandler(w, handlerOpts)
	}

	attrs := []slog.Attr{}
	if opts.Service != "" {
		attrs = append(attrs, slog.String("service", opts.Service))
	}
	if opts.Version != "" {
		attrs = append(attrs, slog.String("version", opts.Version))
	}
	if len(attrs) > 0 {
		handler = handler.WithAttrs(attrs)
	}

	return slog.New(handler)
}
