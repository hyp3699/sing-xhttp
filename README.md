# sing-xhttp

Xray's XHTTP transport ported to the sing-box V2RayTransport interface.

Scope of this port (intentional subset of the upstream):

| Mode | Status | HTTP version |
|---|---|---|
| `packet-up` | implemented | H1.1 (plaintext, raw-socket pool) and H2 (TLS) |
| `stream-up` | implemented | H2 (TLS) only |
| `stream-one` | implemented | H2 (TLS) only (REALITY-style single bidirectional stream) |
| `stream-down` | implemented | H1.1 / H2 / H3 (separate download path/host) |
| `auto` | implemented | defaults to packet-up, or stream-one if REALITY |
| HTTP/3 | implemented | QUIC transport (client + server) |

Why stream-up isn't supported on plaintext H1.1: Go's `net/http` client
buffers chunked request bodies internally, breaking the "never-FIN POST"
requirement. Xray works around this by writing raw HTTP/1.1 to a hijacked
socket (`splithttp/h1_conn.go` + `client.go` HTTP/1.1 branch). This port
includes `h1_conn.go` for reliable HTTP/1.1 packet-up POSTs (raw-socket
pool matching Xray), but stream-up over H1.1 is still not supported since
the body is a streaming pipe that cannot be serialized to a buffer.

## Wire-level interop with stock Xray

Wire-format defaults match Xray's defaults (placement, headers, content
types — everything the server actually parses):
- `sessionId` / `seq` are appended to URL path (`<path>/<sid>` for GET,
  `<path>/<sid>/<seq>` for POST)
- uplink payload goes in the request body
- `x_padding` query parameter inside a `Referer:` header
- response carries `X-Padding`, `Content-Type: text/event-stream`,
  `X-Accel-Buffering: no`, `Cache-Control: no-store`
- uplink POST carries `Content-Type: application/grpc` (stream-up only)

This means a sing-box client built with `sing-xhttp` should talk to a
stock Xray server (`xhttp` transport, default config) and vice versa.

Note: the local *tuning* defaults (POST sizing / pacing) are differentiated
per mode and no longer identical to Xray's fixed 1MB/30ms — see
[Per-mode defaults](#per-mode-defaults). These are local behavior only and
don't affect the wire format or interop.

## Dependencies

The library has **no sing-box dependency**. Direct imports:

- `github.com/sagernet/sing` — interfaces and utilities (network, metadata, tls, logger)
- `github.com/sagernet/quic-go` — http2 / h2c / hpack and QUIC (HTTP/3)
- `golang.org/x/net` — http2 / h2c / hpack
- `github.com/gofrs/uuid/v5` — session id

The `ServerTransport` / `ClientTransport` / `ServerHandler` interfaces in
`xhttp/adapter.go` are structurally identical to sing-box's
`adapter.V2RayServerTransport` / `V2RayClientTransport` /
`V2RayServerTransportHandler` — sing-box's concrete types satisfy them
automatically. This means sing-box can import sing-xhttp without a
circular dependency.

## Integrating with sing-box

Vanilla sing-box doesn't know about "xhttp" — its
`transport/v2ray/transport.go` is a hard-coded switch. To integrate this
library, your sing-box fork should:

1. Add `V2RayTransportTypeXHTTP = "xhttp"` to `constant/v2ray.go`.
2. Add a `XHTTPOptions` field plus its JSON marshal/unmarshal cases to
   `option/V2RayTransportOptions` (declare a `V2RayXHTTPOptions` struct
   mirroring `xhttp.Options`).
3. Add `case C.V2RayTransportTypeXHTTP:` branches to both
   `NewServerTransport` and `NewClientTransport` in
   `transport/v2ray/transport.go`, dispatching to a small bridge file
   that calls `xhttp.NewServer` / `xhttp.NewClient` and converts the
   option struct.

A worked example lives in the author's sing-box fork at
`transport/v2ray/xhttp.go`. The bridge is roughly 80 lines.

Because the `xhttp.ServerTransport` / `xhttp.ClientTransport` /
`xhttp.ServerHandler` interfaces are structurally identical to
sing-box's `adapter.V2RayServerTransport` /
`adapter.V2RayClientTransport` /
`adapter.V2RayServerTransportHandler`, sing-box's concrete types satisfy
our interfaces by Go's structural typing — no wrapping required.

## Config example

Client/server outbound + inbound JSON snippet:

```jsonc
"transport": {
  "type": "xhttp",
  "mode": "packet-up",       // or "stream-up" / "stream-one" / "stream-down" / "auto"
  "path": "/xhttp",
  "host": "example.com",
  // optional — omit to use the per-mode default ({256KB,1MB} for packet-up):
  "sc_max_each_post_bytes": { "from": 1000000, "to": 1000000 },
  "x_padding_bytes":        { "from": 100,     "to": 1000 }
}
```

### Placement / padding obfuscation

Both sides must agree on placement choices. Defaults match stock Xray
(everything on the path, padding via `Referer?x_padding=...`).

```jsonc
"transport": {
  "type": "xhttp",
  "path": "/xhttp",
  // session and seq in headers instead of URL path:
  "session_placement": "header",  // path | query | header | cookie
  "session_key":       "X-Sid",   // defaults: "X-Session" / "x_session"
  "seq_placement":     "header",
  "seq_key":           "X-Sq",

  // padding obfuscation (when off, Referer/x_padding is used — Xray default):
  "x_padding_obfs_mode":  true,
  "x_padding_placement": "header",     // query | header | cookie
  "x_padding_header":    "X-Padding",  // for header placement
  "x_padding_key":       "x_padding",  // for query/cookie placement
  "x_padding_method":    "tokenish"    // repeat-x (default) | tokenish
}
```

### Uplink data placement

Payload can be sent in the request body (default), or encoded as base64
chunks in headers / cookies, matching Xray's `uplinkDataPlacement`:

```jsonc
"transport": {
  "type": "xhttp",
  "path": "/xhttp",
  "uplink_data_placement": "header",  // body (default) | header | cookie | auto
  "uplink_data_key":       "payload",  // required for header/cookie/auto
  "uplink_chunk_size":    { "from": 3000, "to": 4000 }  // optional
}
```

### Custom session ID

```jsonc
"transport": {
  "type": "xhttp",
  "session_id_table":  "Base62",                // predefined name or literal charset
  "session_id_length": { "from": 16, "to": 16 } // omit to use UUID v4
}
```

### stream-down (separate download path)

```jsonc
"transport": {
  "type": "xhttp",
  "mode": "stream-down",
  "path": "/xhttp",
  "download_settings": {
    "host": "download.example.com",
    "path": "/dl"
  }
}
```

Note that the `tokenish` method generates base62 strings whose HPACK
Huffman-encoded byte length targets `x_padding_bytes` (i.e. the *wire*
length after HPACK compression matches the configured range).

### XMUX (multiple H2 connections)

A single HTTP/2 connection is capped by the server's `MAX_CONCURRENT_STREAMS`
(commonly 100 on CDNs). XMUX spreads sessions over a pool of independent
connections and rotates them on time / request-count limits to dodge
per-connection caps. Each pool entry is its own TCP+TLS session.

When `xmux` is absent or empty, the client uses a single connection (legacy
behavior, indistinguishable from earlier versions on the wire).

```jsonc
"transport": {
  "type": "xhttp",
  "path": "/xhttp",
  "xmux": {
    "max_concurrency":     { "from": 16,  "to": 16  }, // in-flight sessions per conn; 0 = unlimited
    "max_connections":     { "from": 4,   "to": 4   }, // simultaneous conns; 0 = unlimited
    "c_max_reuse_times":   { "from": 64,  "to": 128 }, // how many times a conn is picked before retiring
    "h_max_request_times": { "from": 600, "to": 900 }, // sessions served per conn before retiring
    "h_max_reusable_secs": { "from": 1800,"to": 3600 } // wall-clock lifetime per conn (seconds)
  }
}
```

The XMUX field names mirror Xray's so the same config block works on both
sides. Setting `max_connections > 0` with `max_concurrency=0` simply spreads
sessions over up to N conns without per-conn caps.

## Per-mode defaults

When a tuning field is left unset, the default depends on the transport
mode (see `defaultsForMode`). Only the parameters that actually take effect
in a given mode differ; the rest carry sensible placeholder values. An
explicit user value always overrides the mode default (a range with `To == 0`
is treated as "unset").

| Parameter | `packet-up` / `stream-down` / `auto` | `stream-up` / `stream-one` |
|---|---|---|
| `sc_max_each_post_bytes`   | `{256KB, 1MB}` (random) | `{1MB, 1MB}` (unused) |
| `sc_min_posts_interval_ms` | `{10, 30}` ms (random)  | `{30, 30}` (unused) |
| `sc_max_buffered_posts`    | `30` | `30` |
| `sc_stream_up_server_secs` | `{20, 80}` s (unused)   | `{20, 80}` s (heartbeat) |
| `x_padding_bytes`          | `{100, 1000}` | `{100, 1000}` |

Rationale (balanced profile): `packet-up`/`stream-down` carry the uplink as a
stream of POSTs, so a `{256KB,1MB}` random post size mixes throughput with
traffic-shape variety and a `{10,30}`ms random interval cuts latency while
keeping anti-burst jitter. `stream-up`/`stream-one` carry the uplink as a
single long-lived POST, so the post-size/interval knobs don't apply; what
matters is the `{20,80}`s server heartbeat that keeps CDNs from killing the
long POST.

These are all **local behavior** parameters (POST sizing / pacing / heartbeat /
reorder buffer). They never change the wire format — the server never inspects
POST timing — so interop with stock Xray is unaffected.

## Tuning

- `sc_max_each_post_bytes` caps the size of each uplink POST in `packet-up` /
  `stream-down` mode. Smaller values mean more POSTs per MB. Default is a
  random `{256KB, 1MB}` (see per-mode defaults above).
- `sc_max_buffered_posts` (default 30) limits how many out-of-order POSTs
  the server holds before EOF-ing the session. It guards against a client
  sending seq numbers far ahead of what the server can reassemble. Raising
  it does **not** help small-chunk throughput — the bottleneck there is
  per-POST pacing, not the reorder buffer (verified: 30 vs 256 made no
  difference in the benchmark). H2 multiplexes POSTs so the cap rarely
  bites in practice.
- Both client and server must agree on `sc_max_each_post_bytes` — the server
  rejects oversized POSTs.

### Recommended packet-up settings

`packet-up` is inherently a stream of short, high-frequency POSTs, so it
will never match `stream-up` throughput — don't expect it to. The knobs
below trade obfuscation for speed; pick based on what you need.

- **Throughput-first:** raise `sc_max_each_post_bytes` to a fixed `{1MB, 1MB}`
  and leave `sc_min_posts_interval_ms` at its default. Fewer, larger POSTs is
  the single biggest lever (~32 MB/s in the loopback benchmark).
- **Obfuscation-first (small chunks):** if you set a small
  `sc_max_each_post_bytes` (e.g. 16 KB) to blend in, the per-POST pacing
  interval dominates and throughput drops sharply. To recover some of it,
  configure an `xmux` pool with `max_connections > 1`: the pacing interval
  is applied **per connection**, so a session's POSTs fan out across the
  pool and the intervals overlap in parallel. In the benchmark, 16 KB
  chunks go from ~0.5 MB/s (single connection) to ~1.8 MB/s with
  `max_connections: 4` — a 3–4x gain, not free 4x, because a single
  session only spreads over connections the pool has already opened.
- **`sc_min_posts_interval_ms`** defaults to a random `{10, 30}` ms in
  packet-up/stream-down. Lowering it raises throughput at the cost of a more
  bursty, more fingerprintable POST cadence. Setting `{0, 0}` is treated as
  "unset" and restores the mode default — use a small non-zero value like
  `{1, 1}` if you genuinely want to disable pacing.

  Note: the per-connection pacing here intentionally differs from stock
  Xray, which serializes the interval globally. It does not change the wire
  format (the server never inspects POST timing), so interop is unaffected.

## Benchmarks

Loopback echo over a self-signed H2 connection on a 13th-gen i5 laptop. These
are relative-comparison numbers (single machine, no real network), not
absolute throughput claims. Reproduce with:

```sh
GOARCH=amd64 go test ./xhttp/ -run='^$' -bench='Throughput|Dial' -benchtime=50x
```

Benchmarks pin `sc_max_each_post_bytes` explicitly (fixed 1 MB or 16 KB) to
isolate the post-size variable, rather than relying on the per-mode default.

| Benchmark | Throughput | Notes |
|---|---|---|
| stream-up, 1 MB | ~190 MB/s | single long-lived POST, no per-packet overhead |
| packet-up TLS, 1 MB | ~32 MB/s | fixed 1 MB post chunk |
| packet-up plaintext, 1 MB | ~32 MB/s | H1 pool, comparable to H2 at 1 MB chunk |
| packet-up TLS, 1 MB, 16 KB chunks | ~0.5 MB/s | single connection — pacing-bound |
| packet-up TLS, 1 MB, 16 KB chunks, `max_connections: 4` | ~1.8 MB/s | pacing fans out across the pool |

The 16 KB-chunk rows show the per-POST pacing cost: small
`sc_max_each_post_bytes` means many POSTs, each gated by
`sc_min_posts_interval_ms`. On a single connection the intervals serialize;
an `xmux` pool spreads them across connections to recover 3–4x. For real
throughput, keep the per-post chunk near 1 MB, or use stream-up where a
single POST carries the whole uplink.

CPU micro-benchmarks (`-bench='GeneratePadding|ApplyMeta|ApplyPadding'`) show
the request hot path is cheap (~0.4–0.5 µs to place meta), with default-mode
padding being the most expensive step (~2.7 µs, URL clone + query re-encode)
and `tokenish` padding ~20x costlier than `repeat-x` due to its HPACK-length
feedback loop.

## Options validation

`xhttp.Options.Validate()` runs automatically inside `NewClient` / `NewServer`
and rejects inconsistent configuration before any wire activity: unknown mode,
invalid session/seq/padding placements, a session+seq collision on the same
non-path placement and key, unknown padding method, and malformed ranges
(negative bounds or `To < From`). Empty fields are treated as "use default"
and accepted.

## TODO

- [ ] REALITY integration tests — the library detects REALITY via `Config()`
      error and auto-resolves to `stream-one`, but needs end-to-end testing
      with sing-box's REALITY implementation
- [ ] Fully separate download transport (different TLS/dialer for stream-down)
      — currently only path/host can differ; the dialer/TLS is shared. A
      `NewClientWithDownload` constructor could add this if needed
