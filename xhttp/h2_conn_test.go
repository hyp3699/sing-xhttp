package xhttp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestChromeH2ConnFragmentedWrites(t *testing.T) {
	input := chromeH2SourceFrames(t, 1, true)
	want := chromeH2Transform(t, input)

	for chunkSize := 1; chunkSize <= len(input); chunkSize++ {
		t.Run("chunk="+itoa(chunkSize), func(t *testing.T) {
			underlying := &recordingConn{}
			conn := newChromeH2Conn(underlying)
			for offset := 0; offset < len(input); offset += chunkSize {
				end := min(offset+chunkSize, len(input))
				n, err := conn.Write(input[offset:end])
				if err != nil {
					t.Fatalf("Write: %v", err)
				}
				if n != end-offset {
					t.Fatalf("Write = %d, want %d", n, end-offset)
				}
			}
			if got := underlying.Bytes(); !bytes.Equal(got, want) {
				t.Fatalf("transformed bytes differ for chunk size %d", chunkSize)
			}
		})
	}
}

func TestChromeH2ConnCoalescedFrames(t *testing.T) {
	input := chromeH2SourceFrames(t, 1, true)
	underlying := &recordingConn{}
	conn := newChromeH2Conn(underlying)
	if n, err := conn.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write = %d, %v", n, err)
	}

	reader := bytes.NewReader(underlying.Bytes())
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(reader, preface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(nil, reader)
	settings := readFrameAs[*http2.SettingsFrame](t, framer)
	var ids []http2.SettingID
	if err := settings.ForeachSetting(func(setting http2.Setting) error {
		ids = append(ids, setting.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wantIDs := []http2.SettingID{1, 2, 4, 6}
	if !equalSettingIDs(ids, wantIDs) {
		t.Fatalf("SETTINGS IDs = %v, want %v", ids, wantIDs)
	}
	_ = readFrameAs[*http2.WindowUpdateFrame](t, framer)
	headers := readFrameAs[*http2.HeadersFrame](t, framer)
	if !headers.HasPriority() || !headers.Priority.Exclusive || headers.Priority.StreamDep != 0 || headers.Priority.Weight != 146 {
		t.Fatalf("priority = %+v", headers.Priority)
	}
}

func TestChromeH2ConnBatchesFramesPerWrite(t *testing.T) {
	underlying := &recordingConn{}
	conn := newChromeH2Conn(underlying)
	writeChromeH2Preamble(t, conn)

	if got := underlying.writeCalls; got != 1 {
		t.Fatalf("underlying Write calls = %d, want 1", got)
	}
	if got := underlying.writeSizes[0]; got != len(underlying.Bytes()) {
		t.Fatalf("batched write size = %d, recorded bytes = %d", got, len(underlying.Bytes()))
	}
}

func TestChromeH2ConnPriorityDependencies(t *testing.T) {
	underlying := &recordingConn{}
	conn := newChromeH2Conn(underlying).(*chromeH2Conn)
	writeChromeH2Preamble(t, conn)

	writeHeadersFrame(t, conn, 1, false)
	writeHeadersFrame(t, conn, 3, false)
	writeHeadersFrame(t, conn, 5, false)
	assertLastPriority(t, underlying.Bytes(), 5, 3)

	conn.noteLocalEnd(3)
	conn.noteRemoteEnd(3)
	writeHeadersFrame(t, conn, 7, false)
	assertLastPriority(t, underlying.Bytes(), 7, 5)

	conn.removeStream(5)
	writeHeadersFrame(t, conn, 9, false)
	assertLastPriority(t, underlying.Bytes(), 9, 7)
}

func TestChromeH2ConnTrailersHaveNoPriority(t *testing.T) {
	underlying := &recordingConn{}
	conn := newChromeH2Conn(underlying).(*chromeH2Conn)
	writeChromeH2Preamble(t, conn)
	writeHeadersFrame(t, conn, 1, false)
	writeHeadersFrame(t, conn, 1, true)

	frames := parseClientFrames(t, underlying.Bytes())
	var headers []*http2.HeadersFrame
	for _, frame := range frames {
		if frame, ok := frame.(*http2.HeadersFrame); ok {
			headers = append(headers, frame)
		}
	}
	if len(headers) != 2 {
		t.Fatalf("HEADERS count = %d", len(headers))
	}
	if !headers[0].HasPriority() || headers[1].HasPriority() {
		t.Fatalf("initial priority=%v trailer priority=%v", headers[0].HasPriority(), headers[1].HasPriority())
	}
}

func TestChromeH2ConnPriorityRespectsPeerMaxFrameSize(t *testing.T) {
	underlying := &recordingConn{}
	conn := newChromeH2Conn(underlying).(*chromeH2Conn)
	writeChromeH2Preamble(t, conn)
	conn.peerMaxFrameSize.Store(16384)

	fragment := bytes.Repeat([]byte{0x82}, 16384)
	var source bytes.Buffer
	framer := http2.NewFramer(&source, nil)
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: fragment,
		EndHeaders:    true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(source.Bytes()); err != nil {
		t.Fatal(err)
	}

	wire := underlying.Bytes()
	reader := bytes.NewReader(wire[len(http2.ClientPreface):])
	readerFramer := http2.NewFramer(nil, reader)
	var (
		headersLength      uint32
		continuationLength uint32
		headersEnded       bool
		continuationEnded  bool
		gotFragment        []byte
	)
	for reader.Len() > 0 {
		frame, err := readerFramer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch frame := frame.(type) {
		case *http2.HeadersFrame:
			headersLength = frame.Length
			headersEnded = frame.HeadersEnded()
			gotFragment = append(gotFragment, frame.HeaderBlockFragment()...)
		case *http2.ContinuationFrame:
			continuationLength = frame.Length
			continuationEnded = frame.HeadersEnded()
			gotFragment = append(gotFragment, frame.HeaderBlockFragment()...)
		}
	}
	if headersLength == 0 || continuationLength == 0 {
		t.Fatalf("missing split header frames: lengths=%d,%d", headersLength, continuationLength)
	}
	if headersLength > 16384 || continuationLength > 16384 {
		t.Fatalf("frame lengths = %d, %d", headersLength, continuationLength)
	}
	if headersEnded || !continuationEnded {
		t.Fatalf("END_HEADERS: headers=%v continuation=%v", headersEnded, continuationEnded)
	}
	if !bytes.Equal(gotFragment, fragment) {
		t.Fatal("split header block changed")
	}
}

func TestChromeH2ConnFragmentedReadsUpdateLifecycle(t *testing.T) {
	for chunkSize := 1; chunkSize <= 32; chunkSize++ {
		t.Run("chunk="+itoa(chunkSize), func(t *testing.T) {
			underlying := &recordingConn{}
			conn := newChromeH2Conn(underlying).(*chromeH2Conn)
			conn.noteLocalHeaders(1, true)
			conn.noteLocalHeaders(3, true)

			response := buildH2Frame(byte(http2.FrameData), h2FlagEndStream, 3, []byte("ok"))
			for offset := 0; offset < len(response); offset += chunkSize {
				end := min(offset+chunkSize, len(response))
				conn.observeRead(response[offset:end])
			}
			if _, exists := conn.streams[3]; exists {
				t.Fatal("completed stream 3 was not removed")
			}
			if parent := conn.parentStream(5); parent != 1 {
				t.Fatalf("next parent = %d, want 1", parent)
			}
		})
	}
}

func TestChromeH2ConnRSTRemovesStream(t *testing.T) {
	conn := newChromeH2Conn(&recordingConn{}).(*chromeH2Conn)
	conn.noteLocalHeaders(1, false)
	conn.noteLocalHeaders(3, false)
	rst := buildH2Frame(byte(http2.FrameRSTStream), 0, 3, []byte{0, 0, 0, 8})
	conn.observeRead(rst)
	if _, exists := conn.streams[3]; exists {
		t.Fatal("reset stream 3 was not removed")
	}
	if parent := conn.parentStream(5); parent != 1 {
		t.Fatalf("next parent = %d, want 1", parent)
	}
}

func TestChromeH2ConnTracksPeerSettingsAndReencodesHPACK(t *testing.T) {
	underlying := &recordingConn{}
	conn := newChromeH2Conn(underlying).(*chromeH2Conn)
	writeChromeH2Preamble(t, conn)

	var settings bytes.Buffer
	framer := http2.NewFramer(&settings, nil)
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 32768}); err != nil {
		t.Fatal(err)
	}
	conn.observeRead(settings.Bytes())

	var source bytes.Buffer
	encoder := hpack.NewEncoder(&source)
	if err := encoder.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"}); err != nil {
		t.Fatal(err)
	}
	if err := encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := encoder.WriteField(hpack.HeaderField{Name: "x-large", Value: "value"}); err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	frameFramer := http2.NewFramer(&frame, nil)
	if err := frameFramer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: source.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frame.Bytes()); err != nil {
		t.Fatal(err)
	}

	frames := parseClientFrames(t, underlying.Bytes())
	var block bytes.Buffer
	for _, frame := range frames {
		switch frame := frame.(type) {
		case *http2.HeadersFrame:
			block.Write(frame.HeaderBlockFragment())
		case *http2.ContinuationFrame:
			block.Write(frame.HeaderBlockFragment())
		}
	}
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(block.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields[0].Name != ":method" || fields[1].Name != ":authority" || fields[2].Name != "x-large" {
		t.Fatalf("re-encoded fields = %v", fields)
	}
}

func TestChromeH2ConnRejectsUnexpectedInitialSettings(t *testing.T) {
	input := append([]byte(http2.ClientPreface), buildH2Frame(byte(http2.FrameSettings), 0, 0, nil)...)
	conn := newChromeH2Conn(&recordingConn{})
	if _, err := conn.Write(input); !errors.Is(err, errInvalidH2Write) {
		t.Fatalf("Write error = %v, want %v", err, errInvalidH2Write)
	}
	if _, err := conn.Write([]byte("more")); !errors.Is(err, errInvalidH2Write) {
		t.Fatalf("sticky Write error = %v, want %v", err, errInvalidH2Write)
	}
}

func TestChromeH2ConnUnderlyingWriteErrorIsSticky(t *testing.T) {
	wantErr := errors.New("write failed")
	underlying := &recordingConn{writeLimit: 7, writeErr: wantErr}
	conn := newChromeH2Conn(underlying)
	input := chromeH2SourceFrames(t, 1, true)
	if _, err := conn.Write(input); !errors.Is(err, wantErr) {
		t.Fatalf("Write error = %v, want %v", err, wantErr)
	}
	if _, err := conn.Write(input); !errors.Is(err, wantErr) {
		t.Fatalf("sticky Write error = %v, want %v", err, wantErr)
	}
}

func FuzzChromeH2ConnWriteFragmentation(f *testing.F) {
	f.Add([]byte{1, 2, 3, 5, 8, 13})
	f.Add([]byte{255})
	f.Fuzz(func(t *testing.T, chunks []byte) {
		input := chromeH2SourceFrames(t, 1, true)
		want := chromeH2Transform(t, input)
		underlying := &recordingConn{}
		conn := newChromeH2Conn(underlying)
		for offset, i := 0, 0; offset < len(input); i++ {
			chunkSize := 1
			if len(chunks) > 0 {
				chunkSize += int(chunks[i%len(chunks)])
			}
			end := min(offset+chunkSize, len(input))
			if _, err := conn.Write(input[offset:end]); err != nil {
				t.Fatal(err)
			}
			offset = end
		}
		if got := underlying.Bytes(); !bytes.Equal(got, want) {
			t.Fatal("fragment-dependent output")
		}
	})
}

func FuzzChromeH2ConnMalformedInput(f *testing.F) {
	f.Add([]byte(http2.ClientPreface))
	f.Add([]byte{0, 0, 0, byte(http2.FrameSettings), 0, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		conn := newChromeH2Conn(&recordingConn{})
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Write panicked: %v", recovered)
			}
		}()
		_, _ = conn.Write(input)
		_, _ = conn.Write(input)
	})
}

func chromeH2SourceFrames(t testing.TB, streamID uint32, endStream bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	buffer.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&buffer, nil)
	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6 * 1024 * 1024},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 256 * 1024},
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
	); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteWindowUpdate(0, 15*1024*1024-65535); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: []byte{0x82, 0x84, 0x87},
		EndHeaders:    true,
		EndStream:     endStream,
	}); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func chromeH2Transform(t testing.TB, input []byte) []byte {
	t.Helper()
	underlying := &recordingConn{}
	conn := newChromeH2Conn(underlying)
	if _, err := conn.Write(input); err != nil {
		t.Fatal(err)
	}
	return underlying.Bytes()
}

func writeChromeH2Preamble(t testing.TB, conn net.Conn) {
	t.Helper()
	input := chromeH2SourceFrames(t, 1, false)
	// Keep only preface, SETTINGS, and WINDOW_UPDATE.
	input = input[:len(input)-(h2FrameHeaderLen+3)]
	if _, err := conn.Write(input); err != nil {
		t.Fatal(err)
	}
}

func writeHeadersFrame(t testing.TB, conn net.Conn, streamID uint32, endStream bool) {
	t.Helper()
	var buffer bytes.Buffer
	framer := http2.NewFramer(&buffer, nil)
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: []byte{0x82, 0x84, 0x87},
		EndHeaders:    true,
		EndStream:     endStream,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(buffer.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func assertLastPriority(t testing.TB, wire []byte, streamID, parent uint32) {
	t.Helper()
	frames := parseClientFrames(t, wire)
	for i := len(frames) - 1; i >= 0; i-- {
		if headers, ok := frames[i].(*http2.HeadersFrame); ok && headers.StreamID == streamID {
			if !headers.HasPriority() || headers.Priority.StreamDep != parent || !headers.Priority.Exclusive || headers.Priority.Weight != 146 {
				t.Fatalf("stream %d priority = %+v, want parent=%d exclusive=true weight=146", streamID, headers.Priority, parent)
			}
			return
		}
	}
	t.Fatalf("HEADERS stream %d not found", streamID)
}

func parseClientFrames(t testing.TB, wire []byte) []http2.Frame {
	t.Helper()
	if !bytes.HasPrefix(wire, []byte(http2.ClientPreface)) {
		t.Fatal("missing client preface")
	}
	reader := bytes.NewReader(wire[len(http2.ClientPreface):])
	framer := http2.NewFramer(nil, reader)
	var frames []http2.Frame
	for reader.Len() > 0 {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func readFrameAs[T http2.Frame](t testing.TB, framer *http2.Framer) T {
	t.Helper()
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	typed, ok := frame.(T)
	if !ok {
		t.Fatalf("frame = %T", frame)
	}
	return typed
}

func equalSettingIDs(a, b []http2.SettingID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	i := len(buffer)
	for value > 0 {
		i--
		buffer[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[i:])
}

type recordingConn struct {
	bytes.Buffer
	writeLimit int
	writeErr   error
	writeCalls int
	writeSizes []int
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writeCalls++
	c.writeSizes = append(c.writeSizes, len(p))
	if c.writeLimit > 0 && len(p) > c.writeLimit {
		p = p[:c.writeLimit]
	}
	n, _ := c.Buffer.Write(p)
	if c.writeErr != nil {
		return n, c.writeErr
	}
	return n, nil
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingConn) Bytes() []byte                    { return bytes.Clone(c.Buffer.Bytes()) }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }
