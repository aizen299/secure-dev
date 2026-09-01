package scanners

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Registry holds the available scanner adapters.
//
// The registry deliberately knows nothing about any specific scanner: adapters
// are registered from the composition root (cmd/worker), not through package
// init side effects, so the wiring is explicit and testable. Adding a scanner
// touches its own package plus one registration line (§7 rule 4).
type Registry struct {
	mu       sync.RWMutex
	scanners map[string]Scanner
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{scanners: make(map[string]Scanner)}
}

// Register adds a scanner. It fails on a duplicate or empty name rather than
// silently replacing an adapter, because a shadowed scanner would mean a
// security domain stops being covered without anyone noticing.
func (r *Registry) Register(s Scanner) error {
	if s == nil {
		return fmt.Errorf("register: scanner is nil")
	}
	name := s.Name()
	if name == "" {
		return fmt.Errorf("register: scanner name is empty")
	}
	if len(s.Capabilities().Kinds) == 0 {
		return fmt.Errorf("register %q: scanner declares no supported target kinds", name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.scanners[name]; exists {
		return fmt.Errorf("register %q: a scanner with that name is already registered", name)
	}
	r.scanners[name] = s
	return nil
}

// MustRegister panics on failure. For use in composition roots only, where a
// registration error is a programming mistake that must stop startup.
func (r *Registry) MustRegister(s Scanner) {
	if err := r.Register(s); err != nil {
		panic(err)
	}
}

// Get returns the named scanner.
func (r *Registry) Get(name string) (Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scanners[name]
	return s, ok
}

// Names lists every registered scanner, sorted for deterministic output.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SelectFor returns every scanner that supports the given target kind, sorted
// by name so scan composition is deterministic.
//
// This is how the platform chooses scanners. It is capability-driven, so no
// caller ever names a scanner explicitly.
func (r *Registry) SelectFor(kind Kind) []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []Scanner
	for _, s := range r.scanners {
		if s.Capabilities().Supports(kind) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Resolve turns an explicit scanner selection into adapters, reporting any
// name that is not registered. An empty selection means "everything that
// supports this target kind".
func (r *Registry) Resolve(kind Kind, names []string) ([]Scanner, error) {
	if len(names) == 0 {
		selected := r.SelectFor(kind)
		if len(selected) == 0 {
			return nil, fmt.Errorf("no registered scanner supports target kind %q", kind)
		}
		return selected, nil
	}

	out := make([]Scanner, 0, len(names))
	for _, name := range names {
		s, ok := r.Get(name)
		if !ok {
			return nil, fmt.Errorf("scanner %q is not registered", name)
		}
		if !s.Capabilities().Supports(kind) {
			return nil, fmt.Errorf("scanner %q does not support target kind %q", name, kind)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// Provision prepares every registered adapter that needs data in place before
// it can run, returning the failures by scanner name.
//
// Errors are returned rather than acted on: the caller logs them, and the
// adapters stay registered. See the Provisioner doc for why removing a failed
// adapter would be worse than leaving it to fail visibly.
func (r *Registry) Provision(ctx context.Context) map[string]error {
	r.mu.RLock()
	targets := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		targets = append(targets, s)
	}
	r.mu.RUnlock()

	failures := map[string]error{}
	for _, s := range targets {
		p, ok := s.(Provisioner)
		if !ok {
			continue
		}
		if err := p.Provision(ctx); err != nil {
			failures[s.Name()] = err
		}
	}
	return failures
}
