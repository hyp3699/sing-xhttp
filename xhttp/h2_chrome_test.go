package xhttp

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
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

	want := []kv{
		{http2.SettingHeaderTableSize, 65536},
		{http2.SettingEnablePush, 0},
		{http2.SettingInitialWindowSize, 6 * 1024 * 1024},
		{http2.SettingMaxHeaderListSize, 256 * 1024},
	}
	if len(got) != len(want) {
		t.Fatalf("SETTINGS = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SETTINGS[%d] = %+v, want %+v", i, got[i], want[i])
		}
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

	// 4. Request HEADERS use Chromium's RFC 7540 priority tuple.
	frame, err = framer.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	headers, ok := frame.(*http2.HeadersFrame)
	if !ok {
		t.Fatalf("third frame is %T, want *http2.HeadersFrame", frame)
	}
	if !headers.HasPriority() {
		t.Fatal("HEADERS has no priority")
	}
	if got, want := headers.Priority.StreamDep, uint32(0); got != want {
		t.Errorf("HEADERS dependency = %d, want %d", got, want)
	}
	if !headers.Priority.Exclusive {
		t.Error("HEADERS dependency is not exclusive")
	}
	if got, want := headers.Priority.Weight, uint8(146); got != want {
		t.Errorf("HEADERS wire weight = %d, want %d", got, want)
	}

	var block bytes.Buffer
	block.Write(headers.HeaderBlockFragment())
	for !headers.HeadersEnded() {
		frame, err = framer.ReadFrame()
		if err != nil {
			t.Fatalf("read CONTINUATION: %v", err)
		}
		continuation, ok := frame.(*http2.ContinuationFrame)
		if !ok {
			t.Fatalf("header continuation is %T", frame)
		}
		block.Write(continuation.HeaderBlockFragment())
		if continuation.HeadersEnded() {
			break
		}
	}
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(block.Bytes())
	if err != nil {
		t.Fatalf("decode request headers: %v", err)
	}
	var pseudo []string
	for _, field := range fields {
		if field.IsPseudo() {
			pseudo = append(pseudo, field.Name)
		}
	}
	wantPseudo := []string{":method", ":authority", ":scheme", ":path"}
	if len(pseudo) != len(wantPseudo) {
		t.Fatalf("pseudo headers = %v, want %v", pseudo, wantPseudo)
	}
	for i := range wantPseudo {
		if pseudo[i] != wantPseudo[i] {
			t.Fatalf("pseudo headers = %v, want %v", pseudo, wantPseudo)
		}
	}
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

func TestChromeH2RequestPriorityHeader(t *testing.T) {
	baseURL := url.URL{Scheme: "https", Host: "example.com", Path: "/xhttp"}
	newTestClient := func(headers http.Header) *Client {
		options := Options{Path: "/xhttp"}
		return &Client{
			headers: headers,
			codec:   newCodec(options),
		}
	}

	t.Run("default", func(t *testing.T) {
		client := newTestClient(nil)
		req, err := client.newRequestWithTransport(context.Background(), http.MethodGet, &transportSet{
			httpVersion: "2",
			requestURL:  baseURL,
			host:        "example.com",
		}, "session", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Priority"); got != "i" {
			t.Fatalf("Priority = %q, want %q", got, "i")
		}
	})

	t.Run("user value", func(t *testing.T) {
		client := newTestClient(http.Header{"priority": {"u=1"}})
		req, err := client.newRequestWithTransport(context.Background(), http.MethodGet, &transportSet{
			httpVersion: "2",
			requestURL:  baseURL,
			host:        "example.com",
		}, "session", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		var priorityValues []string
		for name, values := range req.Header {
			if strings.EqualFold(name, "priority") {
				priorityValues = append(priorityValues, values...)
			}
		}
		if len(priorityValues) != 1 || priorityValues[0] != "u=1" {
			t.Fatalf("priority values = %v, want [u=1]", priorityValues)
		}
	})

	for _, version := range []string{"1.1", "3"} {
		t.Run("HTTP "+version, func(t *testing.T) {
			client := newTestClient(nil)
			req, err := client.newRequestWithTransport(context.Background(), http.MethodGet, &transportSet{
				httpVersion: version,
				requestURL:  baseURL,
				host:        "example.com",
			}, "session", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Priority"); got != "" {
				t.Fatalf("Priority = %q, want empty", got)
			}
		})
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
