package scanners

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeScanner exists so the registry can be tested without any real adapter.
// The registry must never need to know a concrete scanner.
type fakeScanner struct {
	name string
	caps Capabilities
}

func (f fakeScanner) Name() string               { return f.name }
func (f fakeScanner) Capabilities() Capabilities { return f.caps }
func (f fakeScanner) Version(context.Context) (string, error) {
	return "1.0.0", nil
}
func (f fakeScanner) Scan(context.Context, Target) (RawResult, error) {
	return RawResult{Scanner: f.name}, nil
}

func repoScanner(name string) fakeScanner {
	return fakeScanner{name: name, caps: Capabilities{
		Kinds: []Kind{KindRepository, KindFilesystem}, Categories: []Category{CategorySAST},
	}}
}

func TestRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(repoScanner("alpha")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := r.Get("alpha")
	if !ok {
		t.Fatal("Get returned not-found for a registered scanner")
	}
	if got.Name() != "alpha" {
		t.Errorf("name = %q, want alpha", got.Name())
	}
	if _, ok := r.Get("missing"); ok {
		t.Error("Get returned a scanner that was never registered")
	}
}

// A duplicate name must fail loudly: silently replacing an adapter would drop
// coverage of a security domain without any signal.
func TestRegisterRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(repoScanner("alpha")); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := r.Register(repoScanner("alpha"))
	if err == nil {
		t.Fatal("duplicate registration succeeded")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestRegisterRejectsInvalid(t *testing.T) {
	r := NewRegistry()

	if err := r.Register(nil); err == nil {
		t.Error("nil scanner accepted")
	}
	if err := r.Register(fakeScanner{name: "", caps: Capabilities{Kinds: []Kind{KindRepository}}}); err == nil {
		t.Error("empty name accepted")
	}
	if err := r.Register(fakeScanner{name: "nocaps"}); err == nil {
		t.Error("scanner with no supported kinds accepted")
	}
}

func TestNamesIsSorted(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"zulu", "alpha", "mike"} {
		if err := r.Register(repoScanner(n)); err != nil {
			t.Fatalf("Register(%s): %v", n, err)
		}
	}
	got := r.Names()
	want := []string{"alpha", "mike", "zulu"}
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names() = %v, want %v", got, want)
		}
	}
}

// Selection is capability-driven. This is the test that guards CLAUDE.md §7
// rule 2: the platform picks scanners by what they support, never by name.
func TestSelectForUsesCapabilities(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(fakeScanner{name: "sast", caps: Capabilities{Kinds: []Kind{KindRepository}, Categories: []Category{CategorySAST}}})
	r.MustRegister(fakeScanner{name: "image", caps: Capabilities{Kinds: []Kind{KindImage}, Categories: []Category{CategoryContainer}}})
	r.MustRegister(fakeScanner{name: "both", caps: Capabilities{Kinds: []Kind{KindRepository, KindImage}, Categories: []Category{CategoryDependency}}})

	repo := r.SelectFor(KindRepository)
	if len(repo) != 2 {
		t.Fatalf("SelectFor(repository) returned %d scanners, want 2", len(repo))
	}
	if repo[0].Name() != "both" || repo[1].Name() != "sast" {
		t.Errorf("SelectFor(repository) = %s, %s; want both, sast (sorted)", repo[0].Name(), repo[1].Name())
	}

	if got := r.SelectFor(KindEndpoint); len(got) != 0 {
		t.Errorf("SelectFor(endpoint) returned %d scanners, want 0", len(got))
	}
}

// A newly registered scanner must be picked up by selection with no change to
// selection logic. This is the "adding a scanner costs one line" guarantee.
func TestNewScannerIsSelectedWithoutCoreChanges(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(repoScanner("existing"))

	before := len(r.SelectFor(KindRepository))
	r.MustRegister(fakeScanner{name: "brand-new", caps: Capabilities{
		Kinds: []Kind{KindRepository}, Categories: []Category{CategorySecrets},
	}})
	after := r.SelectFor(KindRepository)

	if len(after) != before+1 {
		t.Fatalf("selection did not include the new scanner: %d -> %d", before, len(after))
	}
	found := false
	for _, s := range after {
		if s.Name() == "brand-new" {
			found = true
		}
	}
	if !found {
		t.Error("newly registered scanner was not selected")
	}
}

func TestResolveExplicitSelection(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(repoScanner("alpha"))
	r.MustRegister(repoScanner("bravo"))
	r.MustRegister(fakeScanner{name: "imageonly", caps: Capabilities{Kinds: []Kind{KindImage}}})

	got, err := r.Resolve(KindRepository, []string{"bravo", "alpha"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 2 || got[0].Name() != "alpha" {
		t.Errorf("Resolve did not return sorted scanners: %v", got)
	}

	// Empty selection means everything that supports the kind.
	all, err := r.Resolve(KindRepository, nil)
	if err != nil {
		t.Fatalf("Resolve(nil): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("Resolve(nil) returned %d, want 2", len(all))
	}
}

func TestResolveErrors(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(repoScanner("alpha"))

	if _, err := r.Resolve(KindRepository, []string{"ghost"}); err == nil {
		t.Error("unregistered scanner name accepted")
	}
	if _, err := r.Resolve(KindImage, []string{"alpha"}); err == nil {
		t.Error("scanner accepted for a kind it does not support")
	}
	if _, err := r.Resolve(KindEndpoint, nil); err == nil {
		t.Error("expected error when no scanner supports the kind")
	}
}

func TestCapabilitiesSupports(t *testing.T) {
	c := Capabilities{Kinds: []Kind{KindRepository, KindImage}}
	if !c.Supports(KindRepository) || !c.Supports(KindImage) {
		t.Error("declared kind not supported")
	}
	if c.Supports(KindEndpoint) {
		t.Error("undeclared kind reported as supported")
	}
	if (Capabilities{}).Supports(KindRepository) {
		t.Error("empty capabilities supported a kind")
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(repoScanner("alpha"))

	done := make(chan struct{})
	for i := range 8 {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			_ = r.SelectFor(KindRepository)
			_ = r.Names()
			_, _ = r.Get("alpha")
			_ = r.Register(repoScanner(string(rune('a'+i)) + "-scanner"))
		}(i)
	}
	for range 8 {
		<-done
	}
}

// provisionable is a scanner that needs data in place before it can run.
type provisionable struct {
	Scanner
	name   string
	err    error
	called int
}

func (p *provisionable) Name() string { return p.name }
func (p *provisionable) Capabilities() Capabilities {
	return Capabilities{Kinds: []Kind{KindFilesystem}, Categories: []Category{CategoryDependency}}
}
func (p *provisionable) Provision(context.Context) error {
	p.called++
	return p.err
}

func TestProvisionOnlyCallsAdaptersThatNeedIt(t *testing.T) {
	r := NewRegistry()
	needs := &provisionable{name: "needs-data"}
	r.MustRegister(needs)
	// A plain adapter must not be required to implement the hook.
	r.MustRegister(fakeScanner{name: "plain",
		caps: Capabilities{Kinds: []Kind{KindFilesystem}, Categories: []Category{CategorySBOM}}})

	if failures := r.Provision(t.Context()); len(failures) != 0 {
		t.Errorf("failures = %v, want none", failures)
	}
	if needs.called != 1 {
		t.Errorf("Provision called %d times, want 1", needs.called)
	}
}

// A provisioning failure must be reported and must NOT remove the adapter. An
// adapter that quietly disappears takes its coverage with it and the scan still
// reports complete coverage -- a false clean.
func TestProvisionFailureKeepsTheAdapterRegistered(t *testing.T) {
	r := NewRegistry()
	broken := &provisionable{name: "broken", err: errors.New("no database")}
	r.MustRegister(broken)

	failures := r.Provision(t.Context())
	if failures["broken"] == nil {
		t.Fatal("a provisioning failure was not reported")
	}
	if _, ok := r.Get("broken"); !ok {
		t.Error("the adapter was unregistered, hiding the loss of coverage")
	}
	if got := r.SelectFor(KindFilesystem); len(got) != 1 {
		t.Errorf("SelectFor returned %d adapters, want 1: it must still be selected and fail visibly", len(got))
	}
}
