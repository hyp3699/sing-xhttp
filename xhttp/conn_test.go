package xhttp

import (
	"errors"
	"net"
	"testing"
)

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestSplitConnNormalizesHTTP2CloseErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "response body", err: errors.New("http2: response body closed")},
		{name: "handler body", err: errors.New("body closed by handler")},
		{name: "client disconnect", err: errors.New("client disconnected")},
	} {
		t.Run(test.name+" read", func(t *testing.T) {
			conn := &splitConn{reader: errorReader{err: test.err}}
			_, err := conn.Read(make([]byte, 1))
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Read error = %v, want a closed connection error", err)
			}
		})
		t.Run(test.name+" write", func(t *testing.T) {
			conn := &splitConn{writer: errorWriter{err: test.err}}
			_, err := conn.Write([]byte("x"))
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Write error = %v, want a closed connection error", err)
			}
		})
	}
}
