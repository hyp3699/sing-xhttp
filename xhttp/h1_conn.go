package xhttp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// H1Conn wraps a raw net.Conn for HTTP/1.1 request/response cycling.
// It tracks unread responses so that a pooled connection can drain stale
// responses before reuse, and buffers the reader side for http.ReadResponse.
//
// This mirrors Xray's splithttp/h1_conn.go: Go's net/http client buffers
// chunked request bodies and has buggy KeepAlive behavior with custom dial
// contexts, so for HTTP/1.1 we serialize the entire request and write it
// raw, then read the response with http.ReadResponse.
type H1Conn struct {
	UnreadedResponsesCount int
	RespBufReader          *bufio.Reader
	conn                   net.Conn
	writeMu                sync.Mutex
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReader(conn),
		conn:          conn,
	}
}

func (c *H1Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.Write(b)
}

func (c *H1Conn) Read(b []byte) (int, error) {
	return c.RespBufReader.Read(b)
}

func (c *H1Conn) Close() error {
	return c.conn.Close()
}

// h1ConnPool manages a pool of H1Conn for HTTP/1.1 uploads.
type h1ConnPool struct {
	pool sync.Pool
	dial func(context.Context) (net.Conn, error)
}

func newH1ConnPool(dial func(context.Context) (net.Conn, error)) *h1ConnPool {
	return &h1ConnPool{
		dial: dial,
		pool: sync.Pool{},
	}
}

// sendH1Request serializes req, writes it over a pooled or fresh H1Conn,
// reads the response, and returns the connection to the pool.
func (p *h1ConnPool) sendH1Request(ctx context.Context, req *http.Request) error {
	buf := &bytes.Buffer{}
	buf.Grow(512 + int(req.ContentLength))
	if err := req.Write(buf); err != nil {
		return err
	}
	reqBytes := buf.Bytes()

	for {
		hc, isNew, err := p.get(ctx)
		if err != nil {
			return err
		}

		// Drain stale responses on reused connections.
		if !isNew && hc.UnreadedResponsesCount > 0 {
			resp, err := http.ReadResponse(hc.RespBufReader, req)
			if err != nil {
				hc.Close()
				if isNew {
					return fmt.Errorf("error while reading stale response: %w", err)
				}
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				hc.Close()
				return fmt.Errorf("got non-200 stale response: %d", resp.StatusCode)
			}
			hc.UnreadedResponsesCount--
		}

		_, err = hc.Write(reqBytes)
		if err == nil {
			hc.UnreadedResponsesCount++
			resp, err := http.ReadResponse(hc.RespBufReader, req)
			if err != nil {
				hc.Close()
				if isNew {
					return err
				}
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				hc.Close()
				return fmt.Errorf("got non-200 response: %d", resp.StatusCode)
			}
			hc.UnreadedResponsesCount--
			p.pool.Put(hc)
			return nil
		}

		hc.Close()
		if isNew {
			return err
		}
	}
}

func (p *h1ConnPool) get(ctx context.Context) (*H1Conn, bool, error) {
	if v := p.pool.Get(); v != nil {
		return v.(*H1Conn), false, nil
	}
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, true, err
	}
	return NewH1Conn(conn), true, nil
}

func (p *h1ConnPool) close() {
	// sync.Pool doesn't expose its contents, so we can't close them.
	// Connections will be GC'd eventually. For a clean shutdown, callers
	// should ensure no more requests are in flight.
}
