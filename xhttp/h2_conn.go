package xhttp

import (
	"bytes"
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	h2FrameHeaderLen = 9
	h2MaxFrameLen    = 1<<24 - 1
	h2MaxHeaderBlock = 16 << 20

	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPriority   = 0x20
)

var errInvalidH2Write = errors.New("xhttp: invalid HTTP/2 write sequence")

// chromeH2Conn adapts the cleartext HTTP/2 byte stream after TLS. It only
// changes frame-level details; x/net/http2 remains responsible for the HTTP/2
// state machine and flow control, while this adapter mirrors the outbound
// HPACK context when it changes header field order.
type chromeH2Conn struct {
	net.Conn

	writeMu        sync.Mutex
	writeBuf       []byte
	writeErr       error
	prefaceWritten bool
	settingsSent   bool
	headerBlock    *outgoingHeaderBlock
	sourceDecoder  *hpack.Decoder
	targetEncoder  *hpack.Encoder
	targetBuffer   bytes.Buffer

	readMu           sync.Mutex
	readBuf          []byte
	peerMaxFrameSize atomic.Uint32
	hpackMu          sync.Mutex

	streamMu sync.Mutex
	streams  map[uint32]*h2StreamState
	order    []uint32
}

type h2StreamState struct {
	localEnded  bool
	remoteEnded bool
}

type outgoingHeaderBlock struct {
	streamID  uint32
	flags     byte
	fragment  []byte
	padLength int
	priority  []byte
	first     bool
}

func newChromeH2Conn(conn net.Conn) net.Conn {
	if _, exists := conn.(*chromeH2Conn); exists {
		return conn
	}
	wrapped := &chromeH2Conn{
		Conn:    conn,
		streams: make(map[uint32]*h2StreamState),
	}
	wrapped.sourceDecoder = hpack.NewDecoder(4096, nil)
	wrapped.sourceDecoder.SetAllowedMaxDynamicTableSize(^uint32(0))
	wrapped.targetEncoder = hpack.NewEncoder(&wrapped.targetBuffer)
	wrapped.targetEncoder.SetMaxDynamicTableSizeLimit(^uint32(0))
	wrapped.peerMaxFrameSize.Store(16384)
	return wrapped
}

func (c *chromeH2Conn) ConnectionState() gotls.ConnectionState {
	if conn, ok := c.Conn.(interface{ ConnectionState() gotls.ConnectionState }); ok {
		return conn.ConnectionState()
	}
	return gotls.ConnectionState{}
}

func (c *chromeH2Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writeBuf = append(c.writeBuf, p...)
	// Keep the transformed frames from one transport flush together. Writing
	// each frame directly to the TLS connection would expose our adapter's
	// frame boundaries as extra application records to passive observers.
	var output []byte
	for {
		if !c.prefaceWritten {
			if len(c.writeBuf) < len(http2.ClientPreface) {
				if !bytes.HasPrefix([]byte(http2.ClientPreface), c.writeBuf) {
					return 0, c.setWriteError(errInvalidH2Write)
				}
				return len(p), nil
			}
			if !bytes.Equal(c.writeBuf[:len(http2.ClientPreface)], []byte(http2.ClientPreface)) {
				return 0, c.setWriteError(errInvalidH2Write)
			}
			output = append(output, c.writeBuf[:len(http2.ClientPreface)]...)
			c.writeBuf = c.writeBuf[len(http2.ClientPreface):]
			c.prefaceWritten = true
		}
		if len(c.writeBuf) == 0 {
			break
		}

		frameLen, complete, err := bufferedH2FrameLen(c.writeBuf)
		if err != nil {
			return 0, c.setWriteError(err)
		}
		if !complete {
			break
		}
		frame := c.writeBuf[:frameLen]
		transformed, err := c.transformWriteFrame(frame)
		if err != nil {
			return 0, c.setWriteError(err)
		}
		output = append(output, transformed...)
		c.writeBuf = c.writeBuf[frameLen:]
	}
	if len(output) > 0 {
		if err := writeAll(c.Conn, output); err != nil {
			return 0, c.setWriteError(err)
		}
	}
	return len(p), nil
}

func (c *chromeH2Conn) setWriteError(err error) error {
	c.writeErr = err
	return err
}

func (c *chromeH2Conn) transformWriteFrame(frame []byte) ([]byte, error) {
	frameType := frame[3]
	flags := frame[4]
	streamID := binary.BigEndian.Uint32(frame[5:9]) & 0x7fffffff

	if !c.settingsSent {
		if frameType != byte(http2.FrameSettings) || flags&h2FlagAck != 0 || streamID != 0 {
			return nil, errInvalidH2Write
		}
		settings, err := chromiumInitialSettings(frame[h2FrameHeaderLen:])
		if err != nil {
			return nil, err
		}
		c.settingsSent = true
		return buildH2Frame(frameType, flags, streamID, settings), nil
	}
	if c.headerBlock != nil && frameType != byte(http2.FrameContinuation) {
		return nil, errInvalidH2Write
	}

	switch http2.FrameType(frameType) {
	case http2.FrameHeaders:
		return c.startHeaderBlock(frame, streamID, flags)
	case http2.FrameContinuation:
		return c.continueHeaderBlock(frame, streamID, flags)
	case http2.FrameData:
		if flags&h2FlagEndStream != 0 {
			c.noteLocalEnd(streamID)
		}
	case http2.FrameRSTStream:
		c.removeStream(streamID)
	}
	return frame, nil
}

func chromiumInitialSettings(payload []byte) ([]byte, error) {
	if len(payload)%6 != 0 {
		return nil, errInvalidH2Write
	}
	values := make(map[uint16]uint32, 5)
	for len(payload) > 0 {
		id := binary.BigEndian.Uint16(payload[:2])
		if _, exists := values[id]; exists {
			return nil, errInvalidH2Write
		}
		values[id] = binary.BigEndian.Uint32(payload[2:6])
		payload = payload[6:]
	}
	want := [...]struct {
		id    uint16
		value uint32
	}{
		{1, 65536},
		{2, 0},
		{4, 6 * 1024 * 1024},
		{6, 256 * 1024},
	}
	if len(values) != len(want)+1 || values[5] != 16384 {
		return nil, errInvalidH2Write
	}
	result := make([]byte, 0, len(want)*6)
	for _, setting := range want {
		value, exists := values[setting.id]
		if !exists || value != setting.value {
			return nil, errInvalidH2Write
		}
		result = binary.BigEndian.AppendUint16(result, setting.id)
		result = binary.BigEndian.AppendUint32(result, setting.value)
	}
	return result, nil
}

func (c *chromeH2Conn) startHeaderBlock(frame []byte, streamID uint32, flags byte) ([]byte, error) {
	payload := frame[h2FrameHeaderLen:]
	fragmentStart := 0
	fragmentEnd := len(payload)
	padLength := 0
	if flags&byte(http2.FlagHeadersPadded) != 0 {
		if len(payload) == 0 {
			return nil, errInvalidH2Write
		}
		padLength = int(payload[0])
		fragmentStart = 1
		fragmentEnd -= padLength
		if fragmentEnd < fragmentStart {
			return nil, errInvalidH2Write
		}
	}
	var priority []byte
	if flags&h2FlagPriority != 0 {
		if fragmentEnd-fragmentStart < 5 {
			return nil, errInvalidH2Write
		}
		priority = bytes.Clone(payload[fragmentStart : fragmentStart+5])
		fragmentStart += 5
	}
	first := c.noteLocalHeaders(streamID, flags&h2FlagEndStream != 0)
	if first && len(priority) == 0 {
		priority = make([]byte, 5)
		binary.BigEndian.PutUint32(priority, c.parentStream(streamID)|1<<31)
		priority[4] = 146 // Chromium LOWEST: wire weight 147 - 1.
	}
	c.headerBlock = &outgoingHeaderBlock{
		streamID:  streamID,
		flags:     flags,
		fragment:  bytes.Clone(payload[fragmentStart:fragmentEnd]),
		padLength: padLength,
		priority:  priority,
		first:     first,
	}
	if len(c.headerBlock.fragment) > h2MaxHeaderBlock {
		return nil, errInvalidH2Write
	}
	if flags&h2FlagEndHeaders == 0 {
		return nil, nil
	}
	return c.finishHeaderBlock()
}

func (c *chromeH2Conn) continueHeaderBlock(frame []byte, streamID uint32, flags byte) ([]byte, error) {
	if c.headerBlock == nil || c.headerBlock.streamID != streamID {
		return nil, errInvalidH2Write
	}
	if flags&^h2FlagEndHeaders != 0 {
		return nil, errInvalidH2Write
	}
	fragment := frame[h2FrameHeaderLen:]
	if len(c.headerBlock.fragment)+len(fragment) > h2MaxHeaderBlock {
		return nil, errInvalidH2Write
	}
	c.headerBlock.fragment = append(c.headerBlock.fragment, fragment...)
	if flags&h2FlagEndHeaders == 0 {
		return nil, nil
	}
	return c.finishHeaderBlock()
}

func (c *chromeH2Conn) finishHeaderBlock() ([]byte, error) {
	block := c.headerBlock
	c.headerBlock = nil
	c.hpackMu.Lock()
	defer c.hpackMu.Unlock()

	tableSizes, err := hpackTableSizeUpdates(block.fragment)
	if err != nil {
		return nil, err
	}
	fields, err := c.sourceDecoder.DecodeFull(block.fragment)
	if err != nil {
		return nil, errInvalidH2Write
	}
	for _, size := range tableSizes {
		c.targetEncoder.SetMaxDynamicTableSize(size)
	}
	fields = chromiumHeaderOrder(fields)
	c.targetBuffer.Reset()
	for _, field := range fields {
		if err := c.targetEncoder.WriteField(field); err != nil {
			return nil, err
		}
	}
	return c.buildHeaderFrames(block, bytes.Clone(c.targetBuffer.Bytes()))
}

func hpackTableSizeUpdates(block []byte) ([]uint32, error) {
	var sizes []uint32
	for len(block) > 0 && block[0]&0xe0 == 0x20 {
		value, consumed, ok := readHPACKVarInt(block, 5)
		if !ok || value > uint64(^uint32(0)) {
			return nil, errInvalidH2Write
		}
		sizes = append(sizes, uint32(value))
		block = block[consumed:]
	}
	return sizes, nil
}

func readHPACKVarInt(buffer []byte, prefix uint8) (uint64, int, bool) {
	if len(buffer) == 0 || prefix == 0 || prefix > 8 {
		return 0, 0, false
	}
	mask := byte(1<<prefix - 1)
	value := uint64(buffer[0] & mask)
	if value < uint64(mask) {
		return value, 1, true
	}
	shift := uint(0)
	for i := 1; i < len(buffer) && i <= 10; i++ {
		b := buffer[i]
		if shift >= 63 && b&0x7f != 0 {
			return 0, 0, false
		}
		value += uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

func chromiumHeaderOrder(fields []hpack.HeaderField) []hpack.HeaderField {
	order := [...]string{":method", ":authority", ":scheme", ":path"}
	result := make([]hpack.HeaderField, 0, len(fields))
	used := make([]bool, len(fields))
	for _, name := range order {
		for i, field := range fields {
			if !used[i] && field.Name == name {
				result = append(result, field)
				used[i] = true
			}
		}
	}
	for i, field := range fields {
		if !used[i] && field.IsPseudo() {
			result = append(result, field)
			used[i] = true
		}
	}
	for i, field := range fields {
		if !used[i] {
			result = append(result, field)
		}
	}
	return result
}

func (c *chromeH2Conn) buildHeaderFrames(block *outgoingHeaderBlock, fragment []byte) ([]byte, error) {
	maxFrameSize := int(c.peerMaxFrameSize.Load())
	padLength := block.padLength
	fixedSize := len(block.priority)
	if block.flags&byte(http2.FlagHeadersPadded) != 0 {
		fixedSize++
	}
	if fixedSize+padLength > maxFrameSize {
		return nil, errInvalidH2Write
	}
	firstFragmentLen := min(len(fragment), maxFrameSize-fixedSize-padLength)
	firstPayload := make([]byte, 0, fixedSize+firstFragmentLen+padLength)
	if block.flags&byte(http2.FlagHeadersPadded) != 0 {
		firstPayload = append(firstPayload, byte(padLength))
	}
	firstPayload = append(firstPayload, block.priority...)
	firstPayload = append(firstPayload, fragment[:firstFragmentLen]...)
	firstPayload = append(firstPayload, make([]byte, padLength)...)

	flags := block.flags
	if len(block.priority) > 0 {
		flags |= h2FlagPriority
	} else {
		flags &^= h2FlagPriority
	}
	remaining := fragment[firstFragmentLen:]
	if len(remaining) == 0 {
		flags |= h2FlagEndHeaders
		return buildH2Frame(byte(http2.FrameHeaders), flags, block.streamID, firstPayload), nil
	}
	flags &^= h2FlagEndHeaders
	result := buildH2Frame(byte(http2.FrameHeaders), flags, block.streamID, firstPayload)
	for len(remaining) > 0 {
		chunkLen := min(len(remaining), maxFrameSize)
		continuationFlags := byte(0)
		if chunkLen == len(remaining) {
			continuationFlags = h2FlagEndHeaders
		}
		result = append(result, buildH2Frame(byte(http2.FrameContinuation), continuationFlags, block.streamID, remaining[:chunkLen])...)
		remaining = remaining[chunkLen:]
	}
	return result, nil
}

func (c *chromeH2Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.observeRead(p[:n])
	}
	return n, err
}

func (c *chromeH2Conn) observeRead(p []byte) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	c.readBuf = append(c.readBuf, p...)
	for {
		frameLen, complete, err := bufferedH2FrameLen(c.readBuf)
		if err != nil {
			c.readBuf = nil
			return
		}
		if !complete {
			return
		}
		frame := c.readBuf[:frameLen]
		flags := frame[4]
		streamID := binary.BigEndian.Uint32(frame[5:9]) & 0x7fffffff
		switch http2.FrameType(frame[3]) {
		case http2.FrameSettings:
			c.observeSettings(frame)
		case http2.FrameHeaders, http2.FrameData:
			if flags&h2FlagEndStream != 0 {
				c.noteRemoteEnd(streamID)
			}
		case http2.FrameRSTStream:
			c.removeStream(streamID)
		}
		c.readBuf = c.readBuf[frameLen:]
	}
}

func (c *chromeH2Conn) observeSettings(frame []byte) {
	if frame[4]&h2FlagAck != 0 || binary.BigEndian.Uint32(frame[5:9])&0x7fffffff != 0 {
		return
	}
	payload := frame[h2FrameHeaderLen:]
	if len(payload)%6 != 0 {
		return
	}
	for len(payload) > 0 {
		id := binary.BigEndian.Uint16(payload[:2])
		value := binary.BigEndian.Uint32(payload[2:6])
		if id == uint16(http2.SettingMaxFrameSize) && value >= 16384 && value <= h2MaxFrameLen {
			c.peerMaxFrameSize.Store(value)
		}
		payload = payload[6:]
	}
}

func (c *chromeH2Conn) noteLocalHeaders(streamID uint32, ended bool) bool {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	state, exists := c.streams[streamID]
	if !exists {
		state = &h2StreamState{}
		c.streams[streamID] = state
		c.order = append(c.order, streamID)
	}
	if ended {
		state.localEnded = true
		c.removeStreamIfDoneLocked(streamID, state)
	}
	return !exists
}

func (c *chromeH2Conn) noteLocalEnd(streamID uint32) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	if state := c.streams[streamID]; state != nil {
		state.localEnded = true
		c.removeStreamIfDoneLocked(streamID, state)
	}
}

func (c *chromeH2Conn) noteRemoteEnd(streamID uint32) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	if state := c.streams[streamID]; state != nil {
		state.remoteEnded = true
		c.removeStreamIfDoneLocked(streamID, state)
	}
}

func (c *chromeH2Conn) parentStream(streamID uint32) uint32 {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	for i := len(c.order) - 1; i >= 0; i-- {
		if c.order[i] != streamID {
			return c.order[i]
		}
	}
	return 0
}

func (c *chromeH2Conn) removeStream(streamID uint32) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	c.removeStreamLocked(streamID)
}

func (c *chromeH2Conn) removeStreamIfDoneLocked(streamID uint32, state *h2StreamState) {
	if state.localEnded && state.remoteEnded {
		c.removeStreamLocked(streamID)
	}
}

func (c *chromeH2Conn) removeStreamLocked(streamID uint32) {
	if _, exists := c.streams[streamID]; !exists {
		return
	}
	delete(c.streams, streamID)
	for i, id := range c.order {
		if id == streamID {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

func bufferedH2FrameLen(buffer []byte) (int, bool, error) {
	if len(buffer) < h2FrameHeaderLen {
		return 0, false, nil
	}
	payloadLen := int(buffer[0])<<16 | int(buffer[1])<<8 | int(buffer[2])
	if payloadLen > h2MaxFrameLen {
		return 0, false, errInvalidH2Write
	}
	frameLen := h2FrameHeaderLen + payloadLen
	return frameLen, len(buffer) >= frameLen, nil
}

func buildH2Frame(frameType, flags byte, streamID uint32, payload []byte) []byte {
	frame := make([]byte, h2FrameHeaderLen, h2FrameHeaderLen+len(payload))
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = frameType
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7fffffff)
	return append(frame, payload...)
}

func writeAll(writer io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := writer.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
