package xhttp

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
)

// TestChromeLikeH2InitialFrames asserts the exact bytes newChromeLikeH2Transport
// puts on the wire before any request: the connection preface, the initial
// SETTINGS frame, and the initial session WINDOW_UPDATE.
//
// The expected values come from Chromium:
//
//	net/http/http_network_session.cc  AddDefaultHttp2Settings()
//	net/spdy/spdy_session.cc          SendInitialData()
//
// This test exists because the two flow-control settings are not plain fields on
// http2.Transport — they are only picked up via http.HTTP2Config through
// ConfigureTransports, and x/net/http2 silently substitutes its own defaults for
// out-of-range values. Asserting on the frames is the only way to know the
// plumbing actually took effect.
func TestChromeLikeH2InitialFrames(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	transport := newChromeLikeH2Transport(
		func(ctx context.Context, network, addr string, cfg *aTLS.STDConfig) (net.Conn, error) {
			return clientConn, nil
		},
		0,
	)

	// RoundTrip will block waiting for the server's SETTINGS, which we never
	// send; we only care about what the client wrote first.
	go func() {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		if err != nil {
			return
		}
		//nolint:bodyclose // never completes; the pipe is closed by the deferred Close
		transport.RoundTrip(req)
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// 1. Connection preface.
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := readFullPipe(serverConn, preface); err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if string(preface) != http2.ClientPreface {
		t.Fatalf("preface = %q, want %q", preface, http2.ClientPreface)
	}

	framer := http2.NewFramer(serverConn, serverConn)

	// 2. SETTINGS.
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatalf("read SETTINGS: %v", err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("first frame is %T, want *http2.SettingsFrame", frame)
	}

	type kv struct {
		ID  http2.SettingID
		Val uint32
	}
	var got []kv
	if err := settings.ForeachSetting(func(s http2.Setting) error {
		got = append(got, kv{s.ID, s.Val})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		t.Logf("SETTINGS 0x%x = %d", uint16(s.ID), s.Val)
	}

	// Values we control must match Chromium exactly.
	want := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,           // kSpdyMaxHeaderTableSize
		http2.SettingEnablePush:        0,               // kSpdyDisablePush
		http2.SettingInitialWindowSize: 6 * 1024 * 1024, // kSpdyStreamMaxRecvWindowSize
		http2.SettingMaxHeaderListSize: 256 * 1024,      // kSpdyMaxHeaderListSize
	}
	seen := make(map[http2.SettingID]uint32, len(got))
	for _, s := range got {
		seen[s.ID] = s.Val
	}
	for id, wantVal := range want {
		gotVal, present := seen[id]
		if !present {
			t.Errorf("SETTINGS 0x%x missing, want %d", uint16(id), wantVal)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("SETTINGS 0x%x = %d, want %d", uint16(id), gotVal, wantVal)
		}
	}

	// Documented residual gap: Chrome omits 0x5 entirely because its value
	// equals the protocol default. x/net/http2 always emits it, but clips an
	// unset Transport.MaxReadFrameSize up to minMaxFrameSize, so the value we
	// send is the same 16384 Chrome relies on — only the presence differs.
	if val, present := seen[http2.SettingMaxFrameSize]; !present {
		t.Log("note: 0x5 MAX_FRAME_SIZE no longer emitted; Chrome parity improved, update docs")
	} else if val != 16384 {
		t.Errorf("SETTINGS 0x5 = %d, want 16384 (the default Chrome relies on)", val)
	}

	// Documented residual gap: Chrome emits settings in ascending id order.
	ascending := true
	for i := 1; i < len(got); i++ {
		if got[i].ID < got[i-1].ID {
			ascending = false
			break
		}
	}
	if ascending {
		t.Log("note: settings now in ascending id order; Chrome parity improved, update docs")
	}

	// 3. Initial session WINDOW_UPDATE on stream 0.
	frame, err = framer.ReadFrame()
	if err != nil {
		t.Fatalf("read WINDOW_UPDATE: %v", err)
	}
	windowUpdate, ok := frame.(*http2.WindowUpdateFrame)
	if !ok {
		t.Fatalf("second frame is %T, want *http2.WindowUpdateFrame", frame)
	}
	if windowUpdate.StreamID != 0 {
		t.Errorf("WINDOW_UPDATE stream = %d, want 0", windowUpdate.StreamID)
	}
	const wantIncrement = 15*1024*1024 - 65535 // 15663105
	if windowUpdate.Increment != wantIncrement {
		t.Errorf("WINDOW_UPDATE increment = %d, want %d", windowUpdate.Increment, wantIncrement)
	}
	t.Logf("WINDOW_UPDATE stream=%d increment=%d", windowUpdate.StreamID, windowUpdate.Increment)
}

// TestChromeLikeH2PingAndIdle pins the PING / idle-connection knobs.
//
// ReadIdleTimeout is passed straight through: 30s by default (see the keepAlive
// comment in NewClientWithDownload — a deliberate departure from Chrome, which
// pings lazily before a write instead of on a timer), 0 when the user disables
// it via h_keep_alive_period: -1.
//
// IdleConnTimeout must stay 0: Chrome has no idle timer for H2 sessions at all
// and keeps them indefinitely for reuse.
func TestChromeLikeH2PingAndIdle(t *testing.T) {
	noop := func(ctx context.Context, network, addr string, cfg *aTLS.STDConfig) (net.Conn, error) {
		return nil, net.ErrClosed
	}
	for _, keepAlive := range []time.Duration{0, 30 * time.Second} {
		transport := newChromeLikeH2Transport(noop, keepAlive)
		if got := transport.ReadIdleTimeout; got != keepAlive {
			t.Errorf("ReadIdleTimeout = %v, want %v", got, keepAlive)
		}
		if got := transport.IdleConnTimeout; got != 0 {
			t.Errorf("IdleConnTimeout = %v, want 0", got)
		}
	}
}

// readFullPipe fills b, tolerating the short reads net.Pipe produces.
func readFullPipe(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
