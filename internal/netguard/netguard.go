// Package netguard classifies network addresses for SSRF protection.
//
// SecureOps accepts target URLs from users and scans them (CLAUDE.md §14.6).
// Without this guard, a caller could point a scan at cloud metadata endpoints,
// internal admin panels, or loopback services and use SecureOps as a proxy into
// the network it runs in.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrBlockedAddress reports that an address is not an allowed scan target.
var ErrBlockedAddress = errors.New("address is not an allowed target")

// Policy decides which addresses may be reached.
type Policy struct {
	// AllowPrivate permits loopback, private, and link-local destinations.
	// It exists for self-hosted deployments that legitimately scan internal
	// hosts. It defaults to false and must be turned on deliberately.
	AllowPrivate bool
}

// cloud instance metadata services. These are link-local and therefore already
// blocked, but they are named explicitly because they are the highest-value
// SSRF target and the block must be obvious to anyone reading this.
var metadataAddresses = []string{
	"169.254.169.254", // AWS, Azure, GCP, DigitalOcean
	"fd00:ec2::254",   // AWS IMDSv2 over IPv6
}

// IsBlocked reports whether ip must not be used as a scan target, and why.
func (p Policy) IsBlocked(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "unparseable address"
	}

	for _, meta := range metadataAddresses {
		if ip.Equal(net.ParseIP(meta)) {
			return true, "cloud instance metadata endpoint"
		}
	}

	// These are never legitimate scan targets, whatever the policy says.
	switch {
	case ip.IsUnspecified():
		return true, "unspecified address"
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast():
		return true, "multicast address"
	}

	if p.AllowPrivate {
		return false, ""
	}

	switch {
	case ip.IsLoopback():
		return true, "loopback address"
	case ip.IsLinkLocalUnicast():
		return true, "link-local address"
	case ip.IsPrivate():
		return true, "private address"
	}

	// IPv4-mapped IPv6 (::ffff:127.0.0.1) would otherwise bypass the checks
	// above, because the IPv6 form is not itself loopback or private.
	if v4 := ip.To4(); v4 != nil && !ip.Equal(v4) {
		return p.IsBlocked(v4)
	}

	return false, ""
}

// Resolver looks up host names. It is an interface so tests do not need DNS.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// CheckHost resolves host and rejects it if any resolved address is blocked.
//
// Every resolved address must pass, not merely one: a hostname that returns
// both a public and a loopback address must be rejected, because which one gets
// dialled is not under our control.
//
// This check is necessary but not sufficient. DNS can return different answers
// between this lookup and the actual connection (DNS rebinding), so the
// connection itself must also be guarded -- see ControlFunc.
func (p Policy) CheckHost(ctx context.Context, resolver Resolver, host string) error {
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrBlockedAddress)
	}

	// A literal IP needs no resolution.
	if ip := net.ParseIP(host); ip != nil {
		if blocked, reason := p.IsBlocked(ip); blocked {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, reason)
		}
		return nil
	}

	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%w: host resolved to no addresses", ErrBlockedAddress)
	}

	for _, addr := range addrs {
		if blocked, reason := p.IsBlocked(addr.IP); blocked {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, reason)
		}
	}
	return nil
}

// ControlFunc returns a net.Dialer Control hook that re-checks the address the
// connection is actually about to use.
//
// This is the defence that survives DNS rebinding: it runs after resolution,
// on the concrete address being dialled, so a hostname that resolved to a
// public IP during validation but a loopback IP at connect time is still
// refused.
func (p Policy) ControlFunc() func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w: unparseable dial address", ErrBlockedAddress)
		}
		ip := net.ParseIP(host)
		if blocked, reason := p.IsBlocked(ip); blocked {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, reason)
		}
		return nil
	}
}
