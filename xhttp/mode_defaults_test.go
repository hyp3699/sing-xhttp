package xhttp

import "testing"

// Verify per-mode default differentiation: packet-up / stream-down get a
// {256KB,1MB} post size and {10,30}ms interval; stream-up / stream-one get the
// large single-post value and no interval tuning relevance.
func TestModeDefaults(t *testing.T) {
	cases := []struct {
		mode            string
		wantPostFrom    int32
		wantPostTo      int32
		wantIntervalMin int32
	}{
		{ModePacketUp, 256 * 1024, 1_000_000, 10},
		{ModeStreamDown, 256 * 1024, 1_000_000, 10},
		{ModeAuto, 256 * 1024, 1_000_000, 10},
		{"", 256 * 1024, 1_000_000, 10},
		{ModeStreamUp, 1_000_000, 1_000_000, 30},
		{ModeStreamOne, 1_000_000, 1_000_000, 30},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			md := defaultsForMode(tc.mode)
			if md.maxEachPostBytes.From != tc.wantPostFrom || md.maxEachPostBytes.To != tc.wantPostTo {
				t.Errorf("post size: got {%d,%d}, want {%d,%d}",
					md.maxEachPostBytes.From, md.maxEachPostBytes.To, tc.wantPostFrom, tc.wantPostTo)
			}
			if md.minPostsIntervalMs.From != tc.wantIntervalMin {
				t.Errorf("interval min: got %d, want %d", md.minPostsIntervalMs.From, tc.wantIntervalMin)
			}
			// stream heartbeat window is uniform across modes.
			if md.streamUpServerSecs.From != 20 || md.streamUpServerSecs.To != 80 {
				t.Errorf("stream-up secs: got {%d,%d}, want {20,80}",
					md.streamUpServerSecs.From, md.streamUpServerSecs.To)
			}
		})
	}
}

// Verify orModeDefault: an explicit user value overrides the mode default,
// but a zero/unset range falls back to it.
func TestOrModeDefault(t *testing.T) {
	def := Range{From: 256 * 1024, To: 1_000_000}
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

// Verify the codec picks up per-mode padding/post defaults via newCodec.
func TestCodecModeDefaults(t *testing.T) {
	pk := newCodec(Options{Mode: ModePacketUp})
	if pk.maxEachPostBytes.From != 256*1024 {
		t.Errorf("packet-up codec post from: got %d, want %d", pk.maxEachPostBytes.From, 256*1024)
	}
	su := newCodec(Options{Mode: ModeStreamUp})
	if su.maxEachPostBytes.From != 1_000_000 {
		t.Errorf("stream-up codec post from: got %d, want %d", su.maxEachPostBytes.From, 1_000_000)
	}
}
