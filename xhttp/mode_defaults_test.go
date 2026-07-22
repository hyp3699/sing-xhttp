package xhttp

import "testing"

// Defaults are Xray-aligned and uniform across modes: {1MB,1MB} post size,
// {30,30}ms interval, {20,80}s stream heartbeat, {100,1000} padding. The
// per-mode function shape is retained for a possible future profile.
func TestModeDefaults(t *testing.T) {
	modes := []string{ModePacketUp, ModeStreamDown, ModeAuto, "", ModeStreamUp, ModeStreamOne}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			md := defaultsForMode(mode)
			if md.maxEachPostBytes != (Range{From: 1_000_000, To: 1_000_000}) {
				t.Errorf("post size: got %+v, want {1000000,1000000}", md.maxEachPostBytes)
			}
			if md.minPostsIntervalMs != (Range{From: 30, To: 30}) {
				t.Errorf("interval: got %+v, want {30,30}", md.minPostsIntervalMs)
			}
			if md.maxBufferedPosts != 30 {
				t.Errorf("buffered posts: got %d, want 30", md.maxBufferedPosts)
			}
			if md.streamUpServerSecs != (Range{From: 20, To: 80}) {
				t.Errorf("stream secs: got %+v, want {20,80}", md.streamUpServerSecs)
			}
			if md.xPaddingBytes != (Range{From: 100, To: 1000}) {
				t.Errorf("padding: got %+v, want {100,1000}", md.xPaddingBytes)
			}
		})
	}
}

// Verify orModeDefault: an explicit user value overrides the mode default,
// but a zero/unset range falls back to it.
func TestOrModeDefault(t *testing.T) {
	def := Range{From: 1_000_000, To: 1_000_000}
	// nil → default
	if got := (*Range)(nil).orModeDefault(def); got != def {
		t.Errorf("nil: got %+v, want %+v", got, def)
	}
	// To==0 → default (treated as unset)
	if got := (&Range{From: 5, To: 0}).orModeDefault(def); got != def {
		t.Errorf("unset: got %+v, want %+v", got, def)
	}
	// explicit → kept
	user := Range{From: 16 * 1024, To: 16 * 1024}
	if got := user.orModeDefault(def); got != user {
		t.Errorf("explicit: got %+v, want %+v", got, user)
	}
}

// Verify the codec picks up the default post size via newCodec (Xray-aligned).
func TestCodecModeDefaults(t *testing.T) {
	for _, mode := range []string{ModePacketUp, ModeStreamUp} {
		c := newCodec(Options{Mode: mode})
		if c.maxEachPostBytes.From != 1_000_000 {
			t.Errorf("%s codec post from: got %d, want %d", mode, c.maxEachPostBytes.From, 1_000_000)
		}
	}
}
