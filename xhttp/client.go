package xhttp

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
)

var _ ClientTransport = (*Client)(nil)

// transportSet bundles everything needed to reach one endpoint: its dialer,
// destination, TLS, request URL, xmux pool and (for HTTP/1.1) the raw-socket
// upload pool. The client holds one for uploads (up) and one for downloads
// (down). When no separate download transport is configured, down == up.
type transportSet struct {
	dialer      N.Dialer
	serverAddr  M.Socksaddr
	tlsConfig   aTLS.Config
	httpVersion string // "1.1", "2", "3"
	isReality   bool
	xmux        *xmuxManager
	requestURL  url.URL
	host        string

	// H1.1 raw socket upload pool (nil when using H2/H3)
	h1Pool *h1ConnPool
}

type Client struct {
	ctx     context.Context
	up      *transportSet
	down    *transportSet
	method  string
	headers http.Header
	opts    Options

	// derived defaults
	codec           *codec
	maxEachPost     Range
	minPostInterval Range
	maxBufferedPost int
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options Options, tlsConfig aTLS.Config) (*Client, error) {
	return NewClientWithDownload(ctx, dialer, serverAddr, options, tlsConfig, nil, M.Socksaddr{}, nil)
}

// NewClientWithDownload is like NewClient but allows a fully separate download
// transport for stream-down mode. When downloadDialer is nil it behaves
// exactly like NewClient (download shares the upload transport, including its
// xmux pool). When provided, the download GET uses its own dialer, destination,
// TLS, xmux pool and request URL (built from options.DownloadSettings host/path
// when set, otherwise derived from downloadAddr).
func NewClientWithDownload(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options Options, tlsConfig aTLS.Config, downloadDialer N.Dialer, downloadAddr M.Socksaddr, downloadTLS aTLS.Config) (*Client, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	// Compute H2 keep-alive period from xmux config.
	var keepAlive time.Duration = 30 * time.Second // Chrome-like default
	if options.Xmux != nil && options.Xmux.HKeepAlivePeriod != 0 {
		keepAlive = time.Duration(options.Xmux.HKeepAlivePeriod) * time.Second
		if keepAlive < 0 {
			keepAlive = 0 // explicitly disable
		}
	}

	// Detect REALITY: REALITY configs return an error from Config().
	isReality := false
	if tlsConfig != nil {
		if _, err := tlsConfig.STDConfig(); err != nil {
			isReality = true
		}
	}

	// Decide HTTP version.
	httpVersion := decideHTTPVersion(tlsConfig, isReality)

	// Resolve mode: auto/empty → packet-up (or stream-one if REALITY).
	mode := options.Mode
	if mode == "" || mode == ModeAuto {
		mode = ModePacketUp
		if isReality {
			mode = ModeStreamOne
			if options.DownloadSettings != nil {
				mode = ModeStreamUp
			}
		}
	}
	options.Mode = mode
	md := defaultsForMode(mode)

	// stream-up/stream-one need HTTP/2+ for bidirectional streaming.
	if (mode == ModeStreamUp || mode == ModeStreamOne) && httpVersion == "1.1" {
		return nil, E.New("xhttp: stream-up/stream-one mode requires HTTP/2 or HTTP/3")
	}

	if options.Method == "" {
		options.Method = http.MethodPost
	}
	if !strings.HasPrefix(options.Path, "/") {
		options.Path = "/" + options.Path
	}

	// Split path and query so that ?key=val in the configured path
	// is preserved in the actual request URL.
	var rawQuery string
	if i := strings.IndexByte(options.Path, '?'); i >= 0 {
		rawQuery = options.Path[i+1:]
		options.Path = options.Path[:i]
	}

	requestURL := buildRequestURL(serverAddr, tlsConfig, options.Path, rawQuery)

	host := options.Host
	if host == "" && tlsConfig != nil {
		host = tlsConfig.ServerName()
	}
	if host == "" {
		host = serverAddr.AddrString()
	}

	up := newTransportSet(dialer, serverAddr, tlsConfig, isReality, httpVersion, keepAlive, options.Xmux, requestURL, host)

	// down defaults to up (shared transport + shared xmux).
	down := up

	// A fully separate download transport was requested.
	if downloadDialer != nil {
		dlReality := false
		if downloadTLS != nil {
			if _, err := downloadTLS.STDConfig(); err != nil {
				dlReality = true
			}
		}
		dlHTTPVersion := decideHTTPVersion(downloadTLS, dlReality)

		// Build the download request URL. Prefer DownloadSettings host/path,
		// otherwise derive from the download destination.
		dlPath := options.Path
		dlRawQuery := rawQuery
		if dl := options.DownloadSettings; dl != nil && dl.Path != "" {
			dlPath = dl.Path
			if !strings.HasPrefix(dlPath, "/") {
				dlPath = "/" + dlPath
			}
			dlRawQuery = ""
			if i := strings.IndexByte(dlPath, '?'); i >= 0 {
				dlRawQuery = dlPath[i+1:]
				dlPath = dlPath[:i]
			}
		}
		dlURL := buildRequestURL(downloadAddr, downloadTLS, dlPath, dlRawQuery)
		if dl := options.DownloadSettings; dl != nil && dl.Host != "" {
			dlURL.Host = dl.Host
		}

		dlHost := ""
		if dl := options.DownloadSettings; dl != nil {
			dlHost = dl.Host
		}
		if dlHost == "" && downloadTLS != nil {
			dlHost = downloadTLS.ServerName()
		}
		if dlHost == "" {
			dlHost = downloadAddr.AddrString()
		}

		down = newTransportSet(downloadDialer, downloadAddr, downloadTLS, dlReality, dlHTTPVersion, keepAlive, options.Xmux, dlURL, dlHost)
	} else if options.DownloadSettings != nil {
		// Shared transport, but a distinct download URL (different path/host).
		// The dialer/TLS/xmux are shared with the upload transport; the GET
		// simply targets a different path/host on the same connection pool.
		dlURL := requestURL
		if dl := options.DownloadSettings; dl != nil {
			if dl.Host != "" {
				dlURL.Host = dl.Host
			}
			if dl.Path != "" {
				dlPath := dl.Path
				if !strings.HasPrefix(dlPath, "/") {
					dlPath = "/" + dlPath
				}
				dlURL.Path = dlPath
			}
		}
		// Copy the upload transport set but override the request URL so the
		// GET goes to the download path while sharing the same xmux pool.
		downCopy := *up
		downCopy.requestURL = dlURL
		if dl := options.DownloadSettings; dl != nil && dl.Host != "" {
			downCopy.host = dl.Host
		}
		down = &downCopy
	}

	c := &Client{
		ctx:             ctx,
		up:              up,
		down:            down,
		method:          options.Method,
		headers:         options.Headers.Build(),
		opts:            options,
		codec:           newCodec(options),
		maxEachPost:     options.ScMaxEachPostBytes.orModeDefault(md.maxEachPostBytes),
		minPostInterval: options.ScMinPostsIntervalMs.orModeDefault(md.minPostsIntervalMs),
		maxBufferedPost: int(options.ScMaxBufferedPosts),
	}

	return c, nil
}

// newTransportSet builds a transportSet: an xmux pool over the given endpoint
// plus (for HTTP/1.1) a raw-socket upload pool. When xmuxOpts is nil an empty
// config is used.
func newTransportSet(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig aTLS.Config, isReality bool, httpVersion string, keepAlive time.Duration, xmuxOpts *XmuxConfig, requestURL url.URL, host string) *transportSet {
	newTransport := buildTransportFactory(dialer, tlsConfig, keepAlive, httpVersion)

	var xmuxCfg XmuxConfig
	if xmuxOpts != nil {
		xmuxCfg = *xmuxOpts
	}
	mgr := newXmuxManager(xmuxCfg, func() *xmuxConn {
		return &xmuxConn{transport: newTransport()}
	})

	ts := &transportSet{
		dialer:      dialer,
		serverAddr:  serverAddr,
		tlsConfig:   tlsConfig,
		httpVersion: httpVersion,
		isReality:   isReality,
		xmux:        mgr,
		requestURL:  requestURL,
		host:        host,
	}

	// For HTTP/1.1, set up a raw-socket upload pool matching Xray's approach.
	// This avoids Go's net/http chunked+keepalive bugs with custom dialers.
	if httpVersion == "1.1" {
		ts.h1Pool = newH1ConnPool(func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", serverAddr)
		})
	}

	return ts
}

// buildRequestURL constructs the base request URL for an endpoint.
func buildRequestURL(serverAddr M.Socksaddr, tlsConfig aTLS.Config, path, rawQuery string) url.URL {
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = serverAddr.String()
	requestURL.Path = path
	requestURL.RawQuery = rawQuery
	return requestURL
}

// decideHTTPVersion determines the HTTP version from the TLS config.
// REALITY forces HTTP/2. NextProtos can specify "http/1.1" or "h3".
func decideHTTPVersion(tlsConfig aTLS.Config, isReality bool) string {
	if isReality {
		return "2"
	}
	if tlsConfig == nil {
		return "1.1"
	}
	nextProtos := tlsConfig.NextProtos()
	if len(nextProtos) == 0 {
		return "2"
	}
	switch nextProtos[0] {
	case "http/1.1":
		return "1.1"
	case "h3":
		return "3"
	default:
		return "2"
	}
}

func (c *Client) Close() error {
	if c.up != nil && c.up.xmux != nil {
		c.up.xmux.Close()
	}
	// Only close the download pool when it is a distinct manager.
	if c.down != nil && c.down.xmux != nil && (c.up == nil || c.down.xmux != c.up.xmux) {
		c.down.xmux.Close()
	}
	return nil
}

// buildTransportFactory returns a function that creates a fresh
// http.RoundTripper per pooled xmuxConn. Plaintext gets a stock
// http.Transport; TLS gets an http2.Transport; HTTP/3 gets an http3.Transport.
func buildTransportFactory(dialer N.Dialer, tlsConfig aTLS.Config, keepAlivePeriod time.Duration, httpVersion string) func() http.RoundTripper {
	if httpVersion == "1.1" {
		httpDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		}
		return func() http.RoundTripper {
			return &http.Transport{
				DialTLSContext:  httpDialContext,
				DialContext:     httpDialContext,
				IdleConnTimeout: 300 * time.Second,
				// chunked transfer download with KeepAlives is buggy with
				// http.Client and our custom dial context.
				DisableKeepAlives: true,
			}
		}
	}
	if httpVersion == "3" {
		// QUIC/HTTP3 needs a concrete *crypto/tls.Config. Obtain it from the
		// sing TLS config's Config() method. REALITY is never applicable here
		// (REALITY forces H2), so a plain STDConfig is fine.
		var gotlsConfig *gotls.Config
		if tlsConfig != nil {
			if cfg, err := tlsConfig.STDConfig(); err == nil {
				gotlsConfig = cfg
			}
		}
		return func() http.RoundTripper {
			var tlsClientConfig *gotls.Config
			if gotlsConfig != nil {
				tlsClientConfig = gotlsConfig.Clone()
			}
			return &http3.Transport{
				TLSClientConfig: tlsClientConfig,
				Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
					udpConn, err := dialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(addr))
					if err != nil {
						return nil, err
					}
					return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), tlsCfg, cfg)
				},
			}
		}
	}
	// HTTP/2 (default for TLS)
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
	}
	return func() http.RoundTripper {
		return &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *aTLS.STDConfig) (net.Conn, error) {
				raw, err := dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
				if err != nil {
					return nil, err
				}
				tlsConn, err := aTLS.ClientHandshake(ctx, raw, tlsConfig)
				if err != nil {
					raw.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			ReadIdleTimeout:            keepAlivePeriod,
			IdleConnTimeout:            300 * time.Second,
			MaxHeaderListSize:          10 << 20, // 10 MB
			StrictMaxConcurrentStreams: true,
		}
	}
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	mode := c.opts.Mode
	if mode == "" || mode == ModeAuto {
		mode = ModePacketUp
	}

	sessionID := ""
	if mode != ModeStreamOne {
		sessionID = c.codec.generateSessionID()
	}

	// Pick the upload connection.
	xc := c.up.xmux.Pick()
	xc.openUsage.Add(1)
	xc.leftRequests.Add(-1)

	// Pick the download connection. When the download transport is separate,
	// it has its own xmux pool and its own openUsage bookkeeping; otherwise
	// the download rides the same connection as the upload.
	xc2 := xc
	if c.down.xmux != c.up.xmux {
		xc2 = c.down.xmux.Pick()
		xc2.openUsage.Add(1)
		xc2.leftRequests.Add(-1)
	}

	switch mode {
	case ModeStreamUp:
		return c.dialStreamUp(ctx, sessionID, xc, xc2)
	case ModeStreamOne:
		return c.dialStreamOne(ctx, sessionID, xc, xc2)
	case ModeStreamDown:
		return c.dialStreamDown(ctx, sessionID, xc, xc2)
	default:
		return c.dialPacketUp(ctx, sessionID, xc, xc2)
	}
}

// --- helpers ---

// releaseUsage decrements openUsage on the upload connection and, when the
// download connection is a distinct pooled client, on the download connection
// too.
func (c *Client) releaseUsage(xc, xc2 *xmuxClient) {
	xc.openUsage.Add(-1)
	if xc2 != nil && xc2 != xc {
		xc2.openUsage.Add(-1)
	}
}

func (c *Client) cloneHeaders() http.Header {
	if c.headers == nil {
		return make(http.Header)
	}
	return c.headers.Clone()
}

// newRequest builds a fresh *http.Request with padding/host applied. The URL
// path embeds sessionID (and seq if non-empty). Uses the upload transport.
func (c *Client) newRequest(ctx context.Context, method, sessionID, seqStr string, body io.Reader) (*http.Request, error) {
	return c.newRequestWithTransport(ctx, method, c.up, sessionID, seqStr, body)
}

// newRequestWithTransport is like newRequest but uses the given transport set's
// base URL and host.
func (c *Client) newRequestWithTransport(ctx context.Context, method string, ts *transportSet, sessionID, seqStr string, body io.Reader) (*http.Request, error) {
	u := ts.requestURL
	u.Path = c.codec.basePath
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Host = ts.host
	req.Header = c.cloneHeaders()
	c.codec.applyMetaToRequest(req, sessionID, seqStr)
	c.codec.applyPaddingToRequest(req)
	return req, nil
}

// openDownload opens the long-lived GET that carries the downlink using the
// download transport set. The returned ReadCloser is the response body and
// lives for the session.
func (c *Client) openDownload(ctx context.Context, sessionID string, xc2 *xmuxClient) (io.ReadCloser, net.Addr, net.Addr, error) {
	req, err := c.newRequestWithTransport(ctx, http.MethodGet, c.down, sessionID, "", nil)
	if err != nil {
		return nil, nil, nil, err
	}

	// Return as soon as the underlying connection is established (GotConn),
	// NOT after the response headers arrive. Middleboxes like Cloudflare
	// buffer the SSE response head until the origin emits body bytes; the
	// origin only emits downlink bytes after it receives the uplink. If we
	// blocked on RoundTrip here, the uplink POSTs would never start and both
	// ends would deadlock (client "read ServerHello: EOF", server "read
	// ClientHello: EOF"). Instead run RoundTrip in the background and hand
	// back a WaitReadCloser whose Read blocks until the body is available.
	gotConn := make(chan struct{})
	var once sync.Once
	signalConn := func() { once.Do(func() { close(gotConn) }) }

	var remoteAddr, localAddr net.Addr
	traceCtx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			remoteAddr = info.Conn.RemoteAddr()
			localAddr = info.Conn.LocalAddr()
			signalConn()
		},
	})
	req = req.WithContext(traceCtx)

	wrc := newWaitReadCloser()
	go func() {
		resp, err := xc2.conn.transport.RoundTrip(req)
		if err != nil {
			signalConn()
			wrc.closeWithError(E.Cause(err, "xhttp: open download"))
			return
		}
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			signalConn()
			wrc.closeWithError(E.New("xhttp: download bad status: ", resp.Status))
			return
		}
		wrc.set(resp.Body)
		signalConn()
	}()

	<-gotConn
	if remoteAddr == nil {
		remoteAddr = c.down.serverAddr.TCPAddr()
	}
	return wrc, remoteAddr, localAddr, nil
}

// --- stream-up ---

func (c *Client) dialStreamUp(ctx context.Context, sessionID string, xc, xc2 *xmuxClient) (net.Conn, error) {
	downBody, remote, local, err := c.openDownload(ctx, sessionID, xc2)
	if err != nil {
		c.releaseUsage(xc, xc2)
		return nil, err
	}

	pr, pw := io.Pipe()
	upReq, err := c.newRequest(ctx, c.method, sessionID, "", pr)
	if err != nil {
		downBody.Close()
		c.releaseUsage(xc, xc2)
		return nil, err
	}
	if !c.opts.NoGRPCHeader {
		upReq.Header.Set("Content-Type", "application/grpc")
	}

	doneOnce := atomic.Bool{}
	closeAll := func() error {
		if doneOnce.Swap(true) {
			return nil
		}
		c.releaseUsage(xc, xc2)
		_ = pw.Close()
		return downBody.Close()
	}

	go func() {
		resp, err := xc.conn.transport.RoundTrip(upReq)
		if err != nil {
			_ = pw.CloseWithError(err)
			_ = downBody.Close()
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = pw.CloseWithError(E.New("xhttp: upload bad status: ", resp.Status))
			_ = downBody.Close()
		}
	}()

	return &splitConn{
		reader:  downBody,
		writer:  pw,
		local:   local,
		remote:  remote,
		onClose: closeAll,
	}, nil
}

// --- stream-one ---

// dialStreamOne opens a single bidirectional HTTP request: the request body
// is the uplink and the response body is the downlink. No session ID is used
// (the server treats requests without a session ID as stream-one). stream-one
// is fully symmetric so it always rides the upload transport; xc2 is only used
// for openUsage bookkeeping when a separate download pool exists.
func (c *Client) dialStreamOne(ctx context.Context, sessionID string, xc, xc2 *xmuxClient) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := c.newRequest(ctx, c.method, sessionID, "", pr)
	if err != nil {
		c.releaseUsage(xc, xc2)
		return nil, err
	}
	if !c.opts.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}

	doneOnce := atomic.Bool{}
	closeAll := func() error {
		if doneOnce.Swap(true) {
			return nil
		}
		c.releaseUsage(xc, xc2)
		_ = pw.Close()
		return nil
	}

	respChan := make(chan struct {
		body   io.ReadCloser
		err    error
		remote net.Addr
		local  net.Addr
	}, 1)

	go func() {
		resp, err := xc.conn.transport.RoundTrip(req)
		if err != nil {
			respChan <- struct {
				body   io.ReadCloser
				err    error
				remote net.Addr
				local  net.Addr
			}{nil, err, nil, nil}
			return
		}
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			respChan <- struct {
				body   io.ReadCloser
				err    error
				remote net.Addr
				local  net.Addr
			}{nil, E.New("xhttp: stream-one bad status: ", resp.Status), nil, nil}
			return
		}
		respChan <- struct {
			body   io.ReadCloser
			err    error
			remote net.Addr
			local  net.Addr
		}{resp.Body, nil, c.up.serverAddr.TCPAddr(), nil}
	}()

	result := <-respChan
	if result.err != nil {
		_ = pw.Close()
		c.releaseUsage(xc, xc2)
		return nil, result.err
	}

	return &splitConn{
		reader:  result.body,
		writer:  pw,
		local:   result.local,
		remote:  result.remote,
		onClose: closeAll,
	}, nil
}

// --- stream-down ---

// dialStreamDown opens separate download and upload channels. The download
// uses a GET request (response body = downlink) on the download transport, and
// the upload uses POSTs with seq numbers (like packet-up) on the upload
// transport. When a separate download transport is configured, the GET rides
// its own dialer/TLS/xmux pool while the POSTs stay on the upload pool.
func (c *Client) dialStreamDown(ctx context.Context, sessionID string, xc, xc2 *xmuxClient) (net.Conn, error) {
	downBody, remote, local, err := c.openDownload(ctx, sessionID, xc2)
	if err != nil {
		c.releaseUsage(xc, xc2)
		return nil, err
	}

	maxEach := int(rangeRand(c.maxEachPost))
	if maxEach < 1 {
		maxEach = 1
	}
	acc := newBatchAccumulator(maxEach)

	uctx, cancel := context.WithCancel(ctx)
	closeOnce := atomic.Bool{}
	closeAll := func() error {
		if closeOnce.Swap(true) {
			return nil
		}
		cancel()
		c.releaseUsage(xc, xc2)
		_ = acc.Close()
		return downBody.Close()
	}

	go c.runPacketUploader(uctx, sessionID, acc, xc, closeAll)

	return &splitConn{
		reader:  downBody,
		writer:  acc,
		local:   local,
		remote:  remote,
		onClose: closeAll,
	}, nil
}

// --- packet-up ---

func (c *Client) dialPacketUp(ctx context.Context, sessionID string, xc, xc2 *xmuxClient) (net.Conn, error) {
	downBody, remote, local, err := c.openDownload(ctx, sessionID, xc2)
	if err != nil {
		c.releaseUsage(xc, xc2)
		return nil, err
	}

	maxEach := int(rangeRand(c.maxEachPost))
	if maxEach < 1 {
		maxEach = 1
	}

	// batchAccumulator batches small writes into larger POST chunks.
	acc := newBatchAccumulator(maxEach)

	uctx, cancel := context.WithCancel(ctx)
	closeOnce := atomic.Bool{}
	closeAll := func() error {
		if closeOnce.Swap(true) {
			return nil
		}
		cancel()
		c.releaseUsage(xc, xc2)
		_ = acc.Close()
		return downBody.Close()
	}

	go c.runPacketUploader(uctx, sessionID, acc, xc, closeAll)

	return &splitConn{
		reader:  downBody,
		writer:  acc,
		local:   local,
		remote:  remote,
		onClose: closeAll,
	}, nil
}

// runPacketUploader drains batched chunks from the accumulator and sends
// them as POST requests, mirroring Xray's splithttp uploader exactly.
//
// The loop is single-threaded and sequential: it drains a chunk, assigns the
// next sequence number, then fires the POST in a goroutine but blocks until
// that request's *body* has been written to the socket (httptrace.WroteRequest)
// — NOT until the response arrives. The response (200 OK) is awaited and
// discarded inside the goroutine. This gives ordered, pipelined uploads whose
// response round-trips overlap in the background, which is essential over
// middleboxes like Cloudflare that would otherwise serialize behind response
// latency or reorder/limit many concurrent POSTs on one H2 connection.
//
// Connection rotation happens only when the bound connection exhausts its
// request/time budget (again matching Xray's dynamicXmuxClient handling).
func (c *Client) runPacketUploader(
	ctx context.Context,
	sessionID string,
	acc *batchAccumulator,
	xc *xmuxClient,
	closeAll func() error,
) {
	var (
		seq       uint64
		lastWrite time.Time
		wg        sync.WaitGroup
		failed    atomic.Bool
	)
	defer wg.Wait()

	for {
		if failed.Load() {
			return
		}

		chunk, err := acc.Drain()
		if err != nil || len(chunk) == 0 {
			return
		}
		if failed.Load() {
			return
		}

		seqStr := strconv.FormatUint(seq, 10)
		seq++

		// Global minimum spacing between POSTs, measured from the last POST's
		// dispatch. Subtracting the elapsed time means that when chunk
		// processing already took longer than the interval, we don't wait at
		// all — this is Xray's "minimum interval" (not a forced interval).
		if c.minPostInterval.From > 0 {
			delay := time.Duration(rangeRand(c.minPostInterval))*time.Millisecond - time.Since(lastWrite)
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}
		}
		lastWrite = time.Now()

		// Rotate the bound connection when it hits its lifetime caps.
		if xc.leftRequests.Add(-1) <= 0 ||
			(!xc.unreusableAt.IsZero() && lastWrite.After(xc.unreusableAt)) {
			newXc := c.up.xmux.Pick()
			newXc.openUsage.Add(1)
			xc.openUsage.Add(-1)
			xc = newXc
		}

		// wroteRequest is closed once the request body is on the socket. The
		// main loop blocks on it so POSTs are dispatched in seq order without
		// waiting for responses.
		wroteRequest := make(chan struct{})
		var wroteOnce sync.Once
		signalWrote := func() { wroteOnce.Do(func() { close(wroteRequest) }) }

		wg.Add(1)
		go func(seqStr string, payload []byte, postXc *xmuxClient) {
			defer wg.Done()
			if postErr := c.sendOnePost(ctx, sessionID, seqStr, payload, postXc, signalWrote); postErr != nil {
				failed.Store(true)
				_ = acc.CloseWithError(postErr)
				_ = closeAll()
			}
			// Ensure the main loop is never left blocked if the request failed
			// before WroteRequest fired.
			signalWrote()
		}(seqStr, chunk, xc)

		// For the raw HTTP/1.1 path there is no httptrace; sendH1Request is
		// synchronous per connection anyway, so just wait for the goroutine's
		// signalWrote (fired at completion). For H2/H3, this unblocks as soon
		// as the body is flushed to the socket.
		select {
		case <-wroteRequest:
		case <-ctx.Done():
			return
		}
	}
}

// sendOnePost sends a single uplink POST. onWrote is invoked via
// httptrace.WroteRequest as soon as the request body has been flushed to the
// socket (H2/H3), letting the uploader loop dispatch the next POST without
// waiting for the response. The response is awaited and discarded here.
func (c *Client) sendOnePost(ctx context.Context, sessionID, seqStr string, payload []byte, xc *xmuxClient, onWrote func()) error {
	req, err := c.newRequest(ctx, c.method, sessionID, seqStr, nil)
	if err != nil {
		return err
	}

	// Encode payload: header/cookie placement encodes into headers/cookies and
	// leaves the body empty; body/auto placement sends it in the request body.
	if c.codec.encodeUplinkPayload(req, payload) {
		if req.Body == nil {
			req.Body = http.NoBody
		}
		req.ContentLength = 0
	} else {
		req.Body = io.NopCloser(bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
	}

	// For HTTP/1.1, use the raw-socket H1Conn pool (matches Xray). The write
	// and response read are synchronous, so signal onWrote after it returns.
	if c.up.h1Pool != nil {
		return c.up.h1Pool.sendH1Request(ctx, req)
	}

	// H2/H3: hook WroteRequest so the uploader loop is released the moment the
	// request body hits the socket, then block here on the response.
	if onWrote != nil {
		trace := &httptrace.ClientTrace{
			WroteRequest: func(httptrace.WroteRequestInfo) { onWrote() },
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

	resp, err := xc.conn.transport.RoundTrip(req)
	if err != nil {
		return E.Cause(err, "xhttp: post packet")
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return E.New("xhttp: post bad status: ", resp.Status)
	}
	return nil
}

// waitReadCloser is an io.ReadCloser whose reads block until the underlying
// body is set (once the background RoundTrip produces the response) or an
// error is recorded. It lets openDownload return at connection-establishment
// time while the HTTP response head is still buffered by a middlebox (CF).
type waitReadCloser struct {
	ready  chan struct{}
	once   sync.Once
	body   io.ReadCloser
	err    error
	closed atomic.Bool
}

func newWaitReadCloser() *waitReadCloser {
	return &waitReadCloser{ready: make(chan struct{})}
}

func (w *waitReadCloser) set(body io.ReadCloser) {
	w.once.Do(func() {
		w.body = body
		close(w.ready)
	})
	// If Close raced ahead of set, close the just-arrived body now.
	if w.closed.Load() && w.body != nil {
		_ = w.body.Close()
	}
}

func (w *waitReadCloser) closeWithError(err error) {
	w.once.Do(func() {
		w.err = err
		close(w.ready)
	})
}

func (w *waitReadCloser) Read(p []byte) (int, error) {
	if w.body == nil {
		<-w.ready
		if w.err != nil {
			return 0, w.err
		}
		if w.body == nil {
			return 0, io.EOF
		}
	}
	return w.body.Read(p)
}

func (w *waitReadCloser) Close() error {
	w.closed.Store(true)
	// Unblock any pending Read.
	w.once.Do(func() { close(w.ready) })
	if w.body != nil {
		return w.body.Close()
	}
	return nil
}
