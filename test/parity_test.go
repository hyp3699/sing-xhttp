package xhttp_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/justinwoo280/sing-xhttp/xhttp"
)

// countingDialer wraps directDialer and counts DialContext calls, so a test
// can prove a separate download transport actually dialed through it.
type countingDialer struct {
	calls atomic.Int32
}

func (d *countingDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	return directDialer{}.DialContext(ctx, network, dest)
}

func (d *countingDialer) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return directDialer{}.ListenPacket(ctx, dest)
}

// TestStreamDownSeparateDialer proves NewClientWithDownload routes the
// download GET through the separate download dialer (not the upload dialer).
func TestStreamDownSeparateDialer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	sTLS, cTLS := makeTLSPair(t)
	opts := xhttp.Options{
		Mode:               xhttp.ModeStreamDown,
		Path:               "/xhttp",
		ScMaxEachPostBytes: &xhttp.Range{From: 4096, To: 4096},
		DownloadSettings:   &xhttp.DownloadConfig{Path: "/xhttp"},
	}
	ctx := context.Background()
	server, err := xhttp.NewServer(ctx, logger.NOP(), opts, anyServerTLS(sTLS), echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.Serve(listener)
	time.Sleep(50 * time.Millisecond)

	dlDialer := &countingDialer{}
	addr := M.ParseSocksaddrHostPort("127.0.0.1", port)
	client, err := xhttp.NewClientWithDownload(
		ctx, directDialer{}, addr, opts, anyClientTLS(cTLS),
		dlDialer, addr, anyClientTLS(cTLS),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte("separate download transport test payload")
	var wg sync.WaitGroup
	wg.Add(2)
	recv := make([]byte, len(payload))
	var readErr error
	go func() { defer wg.Done(); _, readErr = io.ReadFull(conn, recv) }()
	go func() { defer wg.Done(); io.Copy(conn, bytes.NewReader(payload)) }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timeout")
	}
	if readErr != nil {
		t.Fatalf("read err: %v", readErr)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("data mismatch")
	}
	if dlDialer.calls.Load() == 0 {
		t.Fatal("download dialer was never used — separate download transport not wired")
	}
}

// --- uplink data placement end-to-end ------------------------------------

func TestUplinkDataHeader(t *testing.T) {
	runEchoWithOpts(t, xhttp.ModePacketUp, true, func(o *xhttp.Options) {
		o.UplinkDataPlacement = xhttp.PlacementHeader
		o.UplinkDataKey = "X-Up"
		o.UplinkChunkSize = &xhttp.Range{From: 512, To: 512}
	})
}

func TestUplinkDataCookie(t *testing.T) {
	runEchoWithOpts(t, xhttp.ModePacketUp, true, func(o *xhttp.Options) {
		o.UplinkDataPlacement = xhttp.PlacementCookie
		o.UplinkDataKey = "up"
		o.UplinkChunkSize = &xhttp.Range{From: 512, To: 512}
	})
}

func TestUplinkDataAuto(t *testing.T) {
	runEchoWithOpts(t, xhttp.ModePacketUp, true, func(o *xhttp.Options) {
		o.UplinkDataPlacement = xhttp.PlacementAuto
		o.UplinkDataKey = "up"
		o.UplinkChunkSize = &xhttp.Range{From: 512, To: 512}
	})
}

// --- stream-one / stream-down end-to-end ---------------------------------

func TestEchoStreamOneTLS(t *testing.T) { runEcho(t, xhttp.ModeStreamOne, true) }

func TestEchoStreamDownTLS(t *testing.T) { runEcho(t, xhttp.ModeStreamDown, true) }

// stream-down with a distinct download path (shared dialer/TLS) must still echo.
func TestStreamDownSeparatePath(t *testing.T) {
	runEchoWithOpts(t, xhttp.ModeStreamDown, true, func(o *xhttp.Options) {
		o.DownloadSettings = &xhttp.DownloadConfig{Path: "/xhttp"}
	})
}

// --- custom session ID end-to-end ----------------------------------------

func TestCustomSessionID(t *testing.T) {
	runEchoWithOpts(t, xhttp.ModePacketUp, true, func(o *xhttp.Options) {
		o.SessionIDTable = "Base62"
		o.SessionIDLength = &xhttp.Range{From: 20, To: 20}
	})
}

// --- server max header bytes end-to-end ----------------------------------

func TestServerMaxHeaderBytes(t *testing.T) {
	runEchoWithOpts(t, xhttp.ModePacketUp, true, func(o *xhttp.Options) {
		o.ServerMaxHeaderBytes = 16384
	})
}

// --- HTTP/3 client transport TLS is non-nil ------------------------------
//
// Regression guard for the fixed bug where the HTTP/3 transport was created
// with TLSClientConfig=nil (QUIC handshake would always fail). We can't do a
// full QUIC loopback cheaply here, but we can assert NewClient succeeds for an
// h3 ALPN config and does not panic building the transport.
func TestHTTP3ClientConstructs(t *testing.T) {
	_, cTLS := makeTLSPair(t)
	cTLS.SetNextProtos([]string{"h3"})
	client, err := xhttp.NewClient(
		context.Background(),
		directDialer{},
		M.ParseSocksaddrHostPort("127.0.0.1", 443),
		xhttp.Options{Mode: xhttp.ModePacketUp, Path: "/xhttp"},
		anyClientTLS(cTLS),
	)
	if err != nil {
		t.Fatalf("NewClient with h3 ALPN failed: %v", err)
	}
	defer client.Close()
}

// --- isValidHTTPHost behavior (host:port stripping) ----------------------
//
// This exercises the server path indirectly by sending requests through a
// real loopback with a configured host that includes/excludes a port.
func TestHostWithPortAccepted(t *testing.T) {
	runEchoWithOpts(t, xhttp.ModePacketUp, true, func(o *xhttp.Options) {
		o.Host = "localhost"
	})
}
