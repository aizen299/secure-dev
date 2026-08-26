package scanners

import (
	"context"
	"net"
)

// defaultResolver is the system DNS resolver.
type defaultResolver struct{}

func (defaultResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}
