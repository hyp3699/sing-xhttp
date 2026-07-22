package xhttp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// codec encapsulates all wire-format choices: where to put sessionId / seq, and
// how / where to place the x_padding noise. Built once at New(Client|Server)
// time from Options. Used by both client (apply) and server (extract).
type codec struct {
	basePath string

	sessionPlacement string
	sessionKey       string
	seqPlacement     string
	seqKey           string

	xpadObfs      bool
	xpadPlacement string // when obfs: query | header | cookie. else effectively "query-in-header" (Referer / x_padding).
	xpadKey       string
	xpadHeader    string
	xpadMethod    string
	xpadRange     Range

	uplinkDataPlacement string
	uplinkDataKey       string
	uplinkChunkSize     Range
	maxEachPostBytes    Range

	sessionIDTable  string
	sessionIDLength Range
}

func newCodec(o Options) *codec {
	md := defaultsForMode(o.Mode)
	c := &codec{
		basePath:            normalizePath(o.Path),
		sessionPlacement:    o.SessionPlacement,
		sessionKey:          o.SessionKey,
		seqPlacement:        o.SeqPlacement,
		seqKey:              o.SeqKey,
		xpadObfs:            o.XPaddingObfsMode,
		xpadPlacement:       o.XPaddingPlacement,
		xpadKey:             o.XPaddingKey,
		xpadHeader:          o.XPaddingHeader,
		xpadMethod:          o.XPaddingMethod,
		xpadRange:           o.XPaddingBytes.orModeDefault(md.xPaddingBytes),
		uplinkDataPlacement: o.UplinkDataPlacement,
		uplinkDataKey:       o.UplinkDataKey,
		maxEachPostBytes:    o.ScMaxEachPostBytes.orModeDefault(md.maxEachPostBytes),
		sessionIDTable:      o.SessionIDTable,
		sessionIDLength:     o.SessionIDLength.orDefault(0, 0),
	}
	if c.sessionPlacement == "" {
		c.sessionPlacement = PlacementPath
	}
	if c.seqPlacement == "" {
		c.seqPlacement = PlacementPath
	}
	c.sessionKey = defaultKey(c.sessionKey, c.sessionPlacement, "X-Session", "x_session")
	c.seqKey = defaultKey(c.seqKey, c.seqPlacement, "X-Seq", "x_seq")
	if c.xpadObfs {
		if c.xpadPlacement == "" {
			c.xpadPlacement = PlacementHeader
		}
		if c.xpadKey == "" {
			c.xpadKey = "x_padding"
		}
		if c.xpadHeader == "" {
			c.xpadHeader = "X-Padding"
		}
		if c.xpadMethod == "" {
			c.xpadMethod = PaddingMethodRepeatX
		}
	}
	if c.uplinkDataPlacement == "" {
		c.uplinkDataPlacement = PlacementBody
	}
	c.uplinkChunkSize = o.UplinkChunkSize.orDefault(0, 0)
	if c.uplinkChunkSize.To == 0 {
		c.uplinkChunkSize = defaultUplinkChunkSize(c.uplinkDataPlacement, c.maxEachPostBytes)
	}
	if c.uplinkChunkSize.From < 64 {
		c.uplinkChunkSize.From = 64
		if c.uplinkChunkSize.To < 64 {
			c.uplinkChunkSize.To = 64
		}
	}
	return c
}

func defaultKey(set, placement, header, querycookie string) string {
	if set != "" {
		return set
	}
	switch placement {
	case PlacementHeader:
		return header
	case PlacementQuery, PlacementCookie:
		return querycookie
	}
	return ""
}

// --- client side: applyToRequest ------------------------------------------

// applyMetaToRequest writes sessionId/seq into the request per configured placement.
// seqStr may be "" (download GET / stream-up POST).
func (c *codec) applyMetaToRequest(req *http.Request, sessionID, seqStr string) {
	if sessionID != "" {
		applyField(req, c.sessionPlacement, c.sessionKey, sessionID)
	}
	if seqStr != "" {
		applyField(req, c.seqPlacement, c.seqKey, seqStr)
	}
}

func applyField(req *http.Request, placement, key, value string) {
	switch placement {
	case PlacementPath:
		req.URL.Path = appendToPath(req.URL.Path, value)
	case PlacementQuery:
		q := req.URL.Query()
		q.Set(key, value)
		req.URL.RawQuery = q.Encode()
	case PlacementHeader:
		req.Header.Set(key, value)
	case PlacementCookie:
		req.AddCookie(&http.Cookie{Name: key, Value: value, Path: "/"})
	}
}

func appendToPath(p, seg string) string {
	if seg == "" {
		return p
	}
	if strings.HasSuffix(p, "/") {
		return p + seg
	}
	return p + "/" + seg
}

// applyPaddingToRequest writes x_padding into the request per configured placement.
func (c *codec) applyPaddingToRequest(req *http.Request) {
	n := int(rangeRand(c.xpadRange))
	if n <= 0 {
		return
	}
	if !c.xpadObfs {
		// Default: query-in-header with Referer / x_padding=...
		ref := *req.URL
		q := ref.Query()
		q.Set("x_padding", generatePadding(PaddingMethodRepeatX, n))
		ref.RawQuery = q.Encode()
		req.Header.Set("Referer", ref.String())
		return
	}
	value := generatePadding(c.xpadMethod, n)
	switch c.xpadPlacement {
	case PlacementHeader:
		req.Header.Set(c.xpadHeader, value)
	case PlacementQuery:
		q := req.URL.Query()
		q.Set(c.xpadKey, value)
		req.URL.RawQuery = q.Encode()
	case PlacementCookie:
		req.AddCookie(&http.Cookie{Name: c.xpadKey, Value: value, Path: "/"})
	case PlacementQueryInHeader:
		// not normally selected for obfs, but supported for completeness
		ref := *req.URL
		q := ref.Query()
		q.Set(c.xpadKey, value)
		ref.RawQuery = q.Encode()
		req.Header.Set(c.xpadHeader, ref.String())
	}
}

// applyPaddingToResponseHeader writes server-side x_padding into a response.
// Servers default to header placement; under obfs mode the configured header
// placement is honored (cookie/header/query). We don't emit query padding on
// responses because there is no response URL.
func (c *codec) applyPaddingToResponseHeader(w http.ResponseWriter) {
	n := int(rangeRand(c.xpadRange))
	if n <= 0 {
		return
	}
	if !c.xpadObfs {
		w.Header().Set("X-Padding", generatePadding(PaddingMethodRepeatX, n))
		return
	}
	value := generatePadding(c.xpadMethod, n)
	switch c.xpadPlacement {
	case PlacementCookie:
		http.SetCookie(w, &http.Cookie{Name: c.xpadKey, Value: value, Path: "/"})
	case PlacementHeader, PlacementQueryInHeader, PlacementQuery: // query → fall back to header on response
		w.Header().Set(c.xpadHeader, value)
	}
}

// --- server side: extractFromRequest --------------------------------------

// extractMetaFromRequest returns (sessionID, seqStr, pathMatched). pathMatched
// is false iff the request's path doesn't start with the configured base.
func (c *codec) extractMetaFromRequest(r *http.Request) (sessionID, seqStr string, pathMatched bool) {
	if !strings.HasPrefix(r.URL.Path, c.basePath) {
		return "", "", false
	}

	var pathSegs []string
	if c.sessionPlacement == PlacementPath || c.seqPlacement == PlacementPath {
		tail := strings.TrimPrefix(r.URL.Path, c.basePath)
		tail = strings.TrimPrefix(tail, "/")
		if tail != "" {
			pathSegs = strings.Split(tail, "/")
		}
	}
	pi := 0
	take := func() string {
		if pi >= len(pathSegs) {
			return ""
		}
		v := pathSegs[pi]
		pi++
		return v
	}

	sessionID = extractField(r, c.sessionPlacement, c.sessionKey, take)
	seqStr = extractField(r, c.seqPlacement, c.seqKey, take)
	return sessionID, seqStr, true
}

func extractField(r *http.Request, placement, key string, takePath func() string) string {
	switch placement {
	case PlacementPath:
		return takePath()
	case PlacementQuery:
		return r.URL.Query().Get(key)
	case PlacementHeader:
		return r.Header.Get(key)
	case PlacementCookie:
		if ck, err := r.Cookie(key); err == nil {
			return ck.Value
		}
	}
	return ""
}

// --- server side: padding validation --------------------------------------

// extractPaddingFromRequest retrieves the x_padding value from the request
// according to the configured placement and obfuscation mode.
//
// Default mode (obfs=false): padding is in the Referer header as a query
// parameter named "x_padding". Falls back to a direct URL query parameter
// if no Referer is present.
//
// Obfs mode (obfs=true): padding is in the location specified by
// xpadPlacement (header, cookie, query, or queryInHeader).
func (c *codec) extractPaddingFromRequest(r *http.Request) string {
	if !c.xpadObfs {
		// Default: Referer contains URL with ?x_padding=...
		referrer := r.Header.Get("Referer")
		if referrer != "" {
			if refURL, err := url.Parse(referrer); err == nil {
				return refURL.Query().Get("x_padding")
			}
		}
		// Fallback: direct query param.
		return r.URL.Query().Get("x_padding")
	}

	// Obfs mode: try cookie → header → query in sequence (matches Xray).
	if c.xpadKey != "" {
		if ck, err := r.Cookie(c.xpadKey); err == nil && ck != nil && ck.Value != "" {
			return ck.Value
		}
	}

	if c.xpadHeader != "" {
		headerValue := r.Header.Get(c.xpadHeader)
		if headerValue != "" {
			if c.xpadPlacement == PlacementHeader {
				return headerValue
			}
			// queryInHeader: parse the header value as a URL and extract key
			if parsed, err := url.Parse(headerValue); err == nil {
				if v := parsed.Query().Get(c.xpadKey); v != "" {
					return v
				}
			}
		}
	}

	if c.xpadKey != "" {
		if v := r.URL.Query().Get(c.xpadKey); v != "" {
			return v
		}
	}

	return ""
}

// validatePadding checks whether the extracted padding value falls within
// the configured byte range [xpadRange.From, xpadRange.To].
//
// For repeat-x (or default non-obfs mode): the raw string length is checked.
// For tokenish (obfs mode only): the HPACK Huffman-encoded byte length is
// checked, with ±validationTolerance allowance.
//
// Empty padding is always rejected. If xpadRange.To == 0 (unconfigured or
// explicitly zero), validation is skipped (returns true).
func (c *codec) validatePadding(paddingValue string) bool {
	if paddingValue == "" {
		return false
	}

	from := c.xpadRange.From
	to := c.xpadRange.To
	if to <= 0 {
		return true // no range configured — skip validation
	}

	// In default (non-obfs) mode the client always generates repeat-x.
	method := c.xpadMethod
	if !c.xpadObfs {
		method = PaddingMethodRepeatX
	}

	switch method {
	case PaddingMethodTokenish:
		n := int32(hpack.HuffmanEncodeLength(paddingValue))
		f := from - validationTolerance
		t := to + validationTolerance
		if f < 0 {
			f = 0
		}
		return n >= f && n <= t
	default: // repeat-x or unset
		n := int32(len(paddingValue))
		return n >= from && n <= to
	}
}

// --- padding generators ---------------------------------------------------

const charsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const avgHuffmanBytesPerCharBase62 = 0.8
const validationTolerance = 2

func generatePadding(method string, length int) string {
	if length <= 0 {
		return ""
	}
	switch method {
	case PaddingMethodTokenish:
		if s := generateTokenishBase62(length); s != "" {
			return s
		}
		fallthrough
	default:
		return strings.Repeat("X", length)
	}
}

// generateTokenishBase62 produces a random base62 string whose HPACK Huffman
// encoded byte length is within ±validationTolerance of targetHuffmanBytes.
func generateTokenishBase62(targetHuffmanBytes int) string {
	n := int(math.Ceil(float64(targetHuffmanBytes) / avgHuffmanBytesPerCharBase62))
	if n < 1 {
		n = 1
	}
	s, ok := randStringFromCharset(n, charsetBase62)
	if !ok {
		return ""
	}
	const maxIter = 150
	adjust := byte('X')
	for i := 0; i < maxIter; i++ {
		cur := int(hpack.HuffmanEncodeLength(s))
		diff := cur - targetHuffmanBytes
		if diff < 0 {
			if -diff <= validationTolerance {
				return s
			}
			s += string(adjust)
			if adjust == 'X' {
				adjust = 'Z'
			} else {
				adjust = 'X'
			}
		} else {
			if diff <= validationTolerance {
				return s
			}
			if len(s) <= 1 {
				return s
			}
			s = s[:len(s)-1]
		}
	}
	return s
}

func randStringFromCharset(n int, charset string) (string, bool) {
	if n <= 0 || len(charset) == 0 {
		return "", false
	}
	m := len(charset)
	limit := byte(256 - (256 % m))
	out := make([]byte, n)
	i := 0
	buf := make([]byte, 256)
	for i < n {
		if _, err := rand.Read(buf); err != nil {
			return "", false
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out[i] = charset[int(b)%m]
			i++
			if i == n {
				break
			}
		}
	}
	return string(out), true
}

// --- helpers --------------------------------------------------------------

// normalizePath ensures leading and trailing slash, stripping any query.
func normalizePath(p string) string {
	if idx := strings.IndexByte(p, '?'); idx >= 0 {
		p = p[:idx]
	}
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	if p[len(p)-1] != '/' {
		p = p + "/"
	}
	return p
}

// --- uplink data placement (header / cookie) -------------------------------

// encodeUplinkPayload writes payload into request headers or cookies as
// base64-encoded chunks: header key "<key>-0", "<key>-1", ... or cookie
// "<key>_0", "<key>_1", ... For body/auto placement the payload stays in the
// request body (caller handles that). Returns true if payload was placed in
// headers/cookies (meaning body should be empty).
func (c *codec) encodeUplinkPayload(req *http.Request, payload []byte) bool {
	switch c.uplinkDataPlacement {
	case PlacementHeader:
		c.writePayloadToHeaders(req.Header, payload)
		return true
	case PlacementCookie:
		c.writePayloadToCookies(req, payload)
		return true
	}
	// PlacementBody and PlacementAuto both send the payload in the request
	// body on the client side (matching Xray's FillPacketRequest). The server
	// under "auto" concatenates header+cookie+body, so body-only is correct and
	// avoids duplicating the payload.
	return false
}

func (c *codec) writePayloadToHeaders(h http.Header, payload []byte) {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	key := c.uplinkDataKey
	for i := 0; len(encoded) > 0; i++ {
		chunkSize := int(rangeRand(c.uplinkChunkSize))
		if chunkSize > len(encoded) {
			chunkSize = len(encoded)
		}
		h.Set(fmt.Sprintf("%s-%d", key, i), encoded[:chunkSize])
		encoded = encoded[chunkSize:]
	}
}

func (c *codec) writePayloadToCookies(req *http.Request, payload []byte) {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	key := c.uplinkDataKey
	for i := 0; len(encoded) > 0; i++ {
		chunkSize := int(rangeRand(c.uplinkChunkSize))
		if chunkSize > len(encoded) {
			chunkSize = len(encoded)
		}
		req.AddCookie(&http.Cookie{Name: fmt.Sprintf("%s_%d", key, i), Value: encoded[:chunkSize]})
		encoded = encoded[chunkSize:]
	}
}

// decodeUplinkPayload extracts payload from the request. For body placement
// it returns nil (caller reads body). For auto it tries header + cookie + body.
// The bodyBytes parameter is the already-read body payload (may be nil).
func (c *codec) decodeUplinkPayload(r *http.Request, bodyPayload []byte) []byte {
	switch c.uplinkDataPlacement {
	case PlacementBody:
		return bodyPayload
	case PlacementHeader:
		return c.readPayloadFromHeaders(r.Header)
	case PlacementCookie:
		return c.readPayloadFromCookies(r)
	case PlacementAuto:
		header := c.readPayloadFromHeaders(r.Header)
		cookie := c.readPayloadFromCookies(r)
		return concatBytes(header, cookie, bodyPayload)
	}
	return bodyPayload
}

func (c *codec) readPayloadFromHeaders(h http.Header) []byte {
	key := c.uplinkDataKey
	var chunks []string
	for i := 0; ; i++ {
		chunk := h.Get(fmt.Sprintf("%s-%d", key, i))
		if chunk == "" {
			break
		}
		chunks = append(chunks, chunk)
	}
	if len(chunks) == 0 {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.Join(chunks, ""))
	if err != nil {
		return nil
	}
	return decoded
}

func (c *codec) readPayloadFromCookies(r *http.Request) []byte {
	key := c.uplinkDataKey
	var chunks []string
	for i := 0; ; i++ {
		cookie, err := r.Cookie(fmt.Sprintf("%s_%d", key, i))
		if err != nil || cookie == nil {
			break
		}
		chunks = append(chunks, cookie.Value)
	}
	if len(chunks) == 0 {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.Join(chunks, ""))
	if err != nil {
		return nil
	}
	return decoded
}

func concatBytes(parts ...[]byte) []byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// --- custom session ID generation -------------------------------------------

// generateSessionID returns a session ID. If sessionIDTable and
// sessionIDLength are configured, generates a random string from the table.
// Otherwise returns a UUID.
func (c *codec) generateSessionID() string {
	table := c.sessionIDTable
	if predefined, ok := PredefinedTable[table]; ok {
		table = predefined
	}
	length := int(c.sessionIDLength.From)
	if c.sessionIDLength.To > c.sessionIDLength.From {
		length = int(rangeRand(c.sessionIDLength))
	}
	if table != "" && length > 0 {
		if s, ok := randStringFromCharset(length, table); ok {
			return s
		}
	}
	return newUUID()
}
