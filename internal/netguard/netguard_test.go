package netguard

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

type stubResolver struct {
	addrs []net.IPAddr
	err   error
}

func (s stubResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return s.addrs, s.err
}

func ips(list ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(list))
	for _, s := range list {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out
}

func TestIsBlockedDefaultPolicy(t *testing.T) {
	p := Policy{}

	blocked := map[string]string{
		"127.0.0.1":        "loopback",
		"127.0.0.53":       "loopback (systemd-resolved)",
		"::1":              "IPv6 loopback",
		"10.0.0.5":         "private class A",
		"172.16.3.4":       "private class B",
		"192.168.1.10":     "private class C",
		"169.254.169.254":  "cloud metadata",
		"169.254.1.1":      "link-local",
		"fd00:ec2::254":    "AWS IPv6 metadata",
		"fe80::1":          "IPv6 link-local",
		"fc00::1":          "IPv6 unique local",
		"0.0.0.0":          "unspecified",
		"::":               "IPv6 unspecified",
		"224.0.0.1":        "multicast",
		"::ffff:127.0.0.1": "IPv4-mapped loopback",
		"::ffff:10.0.0.1":  "IPv4-mapped private",
	}
	for addr, why := range blocked {
		t.Run("blocked/"+addr, func(t *testing.T) {
			got, reason := p.IsBlocked(net.ParseIP(addr))
			if !got {
				t.Errorf("%s (%s) was allowed, want blocked", addr, why)
			}
			if reason == "" {
				t.Error("blocked address returned no reason")
			}
		})
	}

	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}
	for _, addr := range allowed {
		t.Run("allowed/"+addr, func(t *testing.T) {
			if blocked, reason := p.IsBlocked(net.ParseIP(addr)); blocked {
				t.Errorf("public address %s was blocked as %q", addr, reason)
			}
		})
	}
}

func TestIsBlockedNilAddress(t *testing.T) {
	if blocked, _ := (Policy{}).IsBlocked(nil); !blocked {
		t.Error("nil IP was allowed")
	}
	// An unparseable host string yields a nil IP and must not slip through.
	if blocked, _ := (Policy{}).IsBlocked(net.ParseIP("not-an-ip")); !blocked {
		t.Error("unparseable IP was allowed")
	}
}

func TestAllowPrivateOptIn(t *testing.T) {
	p := Policy{AllowPrivate: true}

	for _, addr := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "::1"} {
		if blocked, reason := p.IsBlocked(net.ParseIP(addr)); blocked {
			t.Errorf("AllowPrivate did not permit %s: %s", addr, reason)
		}
	}

	// Metadata endpoints and multicast stay blocked even when private ranges
	// are permitted: they are never a legitimate scan target.
	for _, addr := range []string{"169.254.169.254", "fd00:ec2::254", "224.0.0.1", "0.0.0.0"} {
		if blocked, _ := p.IsBlocked(net.ParseIP(addr)); !blocked {
			t.Errorf("AllowPrivate wrongly permitted %s", addr)
		}
	}
}

func TestCheckHostLiteralIP(t *testing.T) {
	p := Policy{}
	if err := p.CheckHost(t.Context(), stubResolver{}, "8.8.8.8"); err != nil {
		t.Errorf("public literal IP rejected: %v", err)
	}
	err := p.CheckHost(t.Context(), stubResolver{}, "127.0.0.1")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("loopback literal IP: err = %v, want ErrBlockedAddress", err)
	}
}

func TestCheckHostResolves(t *testing.T) {
	p := Policy{}
	if err := p.CheckHost(t.Context(), stubResolver{addrs: ips("93.184.216.34")}, "example.com"); err != nil {
		t.Errorf("public host rejected: %v", err)
	}
	err := p.CheckHost(t.Context(), stubResolver{addrs: ips("127.0.0.1")}, "localtest.me")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("host resolving to loopback: err = %v, want ErrBlockedAddress", err)
	}
}

// A hostname returning both a public and a private address must be rejected:
// we do not control which one the scanner's own resolver will pick.
func TestCheckHostRejectsMixedResolution(t *testing.T) {
	err := Policy{}.CheckHost(t.Context(),
		stubResolver{addrs: ips("93.184.216.34", "169.254.169.254")}, "sneaky.example")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("mixed resolution: err = %v, want ErrBlockedAddress", err)
	}
}

func TestCheckHostEdgeCases(t *testing.T) {
	p := Policy{}

	if err := p.CheckHost(t.Context(), stubResolver{}, ""); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("empty host: err = %v, want ErrBlockedAddress", err)
	}
	if err := p.CheckHost(t.Context(), stubResolver{addrs: nil}, "void.example"); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("no addresses: err = %v, want ErrBlockedAddress", err)
	}
	resolveErr := errors.New("nxdomain")
	if err := p.CheckHost(t.Context(), stubResolver{err: resolveErr}, "nope.example"); !errors.Is(err, resolveErr) {
		t.Errorf("resolver failure not propagated: %v", err)
	}
}

// ControlFunc is the rebinding-resistant check: it runs on the address actually
// being dialled, after resolution.
func TestControlFunc(t *testing.T) {
	control := Policy{}.ControlFunc()

	if err := control("tcp4", "93.184.216.34:443", syscall.RawConn(nil)); err != nil {
		t.Errorf("public address rejected at dial time: %v", err)
	}
	for _, addr := range []string{"127.0.0.1:8080", "169.254.169.254:80", "10.1.2.3:443", "[::1]:443"} {
		if err := control("tcp", addr, syscall.RawConn(nil)); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("dial to %s: err = %v, want ErrBlockedAddress", addr, err)
		}
	}
	if err := control("tcp", "malformed", syscall.RawConn(nil)); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("malformed dial address: err = %v, want ErrBlockedAddress", err)
	}
}
