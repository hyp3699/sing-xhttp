package xhttp

import (
	"context"
	"errors"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type unsupportedH3TLS struct {
	nextProtos []string
}

func (c *unsupportedH3TLS) ServerName() string { return "example.com" }

func (c *unsupportedH3TLS) SetServerName(string) {}

func (c *unsupportedH3TLS) NextProtos() []string { return c.nextProtos }

func (c *unsupportedH3TLS) SetNextProtos(nextProtos []string) { c.nextProtos = nextProtos }

func (c *unsupportedH3TLS) STDConfig() (*aTLS.STDConfig, error) {
	return nil, errors.New("unsupported custom TLS")
}

func (c *unsupportedH3TLS) Client(net.Conn) (aTLS.Conn, error) { return nil, nil }

func (c *unsupportedH3TLS) Clone() aTLS.Config {
	clone := *c
	clone.nextProtos = append([]string(nil), c.nextProtos...)
	return &clone
}

var _ aTLS.Config = (*unsupportedH3TLS)(nil)

type h3ValidationDialer struct{}

func (h3ValidationDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not reached")
}

func (h3ValidationDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not reached")
}

var _ N.Dialer = h3ValidationDialer{}

func TestHTTP3RejectsCustomTLS(t *testing.T) {
	_, err := NewClient(
		context.Background(),
		h3ValidationDialer{},
		M.ParseSocksaddrHostPort("127.0.0.1", 443),
		Options{Mode: ModePacketUp, Path: "/xhttp"},
		&unsupportedH3TLS{nextProtos: []string{"h3"}},
	)
	if err == nil {
		t.Fatal("NewClient accepted custom TLS for HTTP/3")
	}
	const want = "xhttp: HTTP/3 requires a standard TLS client: uTLS and REALITY are not supported over QUIC, they only support HTTP/1.1 and HTTP/2"
	if got := err.Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

// TestHTTP3KeepsRealityOnHTTP2 pins the untouched REALITY path: REALITY is
// hard-bound to uTLS and only speaks HTTP/1.1 or HTTP/2, so it stays forced to
// HTTP/2 regardless of the ALPN list it carries.
func TestHTTP3KeepsRealityOnHTTP2(t *testing.T) {
	if got := decideHTTPVersion(&unsupportedH3TLS{nextProtos: []string{"h2", "http/1.1"}}, true); got != "2" {
		t.Fatalf("REALITY HTTP version = %q, want 2", got)
	}
	if got := decideHTTPVersion(&unsupportedH3TLS{nextProtos: []string{"h3"}}, true); got != "2" {
		t.Fatalf("REALITY HTTP version = %q, want 2", got)
	}
}

// TestHTTP3AcceptsStandardTLS proves the guard only fires for TLS
// implementations that cannot produce a standard *tls.Config.
func TestHTTP3AcceptsStandardTLS(t *testing.T) {
	if err := validateHTTP3TLS(nil); err != nil {
		t.Fatalf("plaintext rejected: %v", err)
	}
	if err := validateHTTP3TLS(&unsupportedH3TLS{nextProtos: []string{"h2", "http/1.1"}}); err != nil {
		t.Fatalf("non-h3 custom TLS rejected: %v", err)
	}
}
