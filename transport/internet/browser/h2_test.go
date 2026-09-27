package browser_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"

	. "github.com/xtls/xray-core/transport/internet/browser"
	"golang.org/x/net/http2"
)

// recordingConn keeps a copy of everything the client sent.
type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.buf.Write(b[:n])
	c.mu.Unlock()
	return n, err
}

func (c *recordingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf.Bytes())
}

const bodySize = 20 << 20

func startServer(t *testing.T) (string, chan *recordingConn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	conns := make(chan *recordingConn, 16)
	h2s := &http2.Server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			n, _ := io.Copy(io.Discard, r.Body)
			if n != bodySize {
				w.WriteHeader(http.StatusBadRequest)
			}
			return
		}
		w.Write(bytes.Repeat([]byte{'x'}, bodySize))
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			rc := &recordingConn{Conn: c}
			conns <- rc
			go h2s.ServeConn(rc, &http2.ServeConnOpts{Handler: handler})
		}
	}()
	return ln.Addr().String(), conns
}

type frameSummary struct {
	settings     []http2.Setting
	windowUpdate uint32
	headers      []http2.PriorityParam
	headersPrio  []bool
}

func parseClientFrames(t *testing.T, raw []byte) frameSummary {
	t.Helper()
	if !bytes.HasPrefix(raw, []byte(http2.ClientPreface)) {
		t.Fatal("no client preface")
	}
	fr := http2.NewFramer(nil, bytes.NewReader(raw[len(http2.ClientPreface):]))
	var s frameSummary
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return s
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() && s.settings == nil {
				f.ForeachSetting(func(st http2.Setting) error {
					s.settings = append(s.settings, st)
					return nil
				})
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 && s.windowUpdate == 0 {
				s.windowUpdate = f.Increment
			}
		case *http2.HeadersFrame:
			s.headers = append(s.headers, f.Priority)
			s.headersPrio = append(s.headersPrio, f.HasPriority())
		}
	}
}

func TestH2Profiles(t *testing.T) {
	for _, p := range []*H2Profile{Chrome, Firefox} {
		t.Run(p.Name, func(t *testing.T) {
			addr, conns := startServer(t)
			tr := p.NewTransport()
			tr.AllowHTTP = true
			tr.DialTLSContext = func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return p.Conn(c), nil
			}
			client := &http.Client{Transport: tr}
			defer tr.CloseIdleConnections()

			for i := 0; i < 3; i++ {
				resp, err := client.Get("http://example.com/")
				if err != nil {
					t.Fatal(err)
				}
				n, err := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if err != nil || n != bodySize {
					t.Fatalf("download: %d bytes, %v", n, err)
				}
				resp, err = client.Post("http://example.com/", "application/octet-stream", bytes.NewReader(make([]byte, bodySize)))
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("upload: status %d", resp.StatusCode)
				}
			}

			sum := parseClientFrames(t, (<-conns).bytes())
			if len(sum.settings) != len(p.Settings) {
				t.Fatalf("settings %v, want %v", sum.settings, p.Settings)
			}
			for i := range p.Settings {
				if sum.settings[i] != p.Settings[i] {
					t.Fatalf("settings %v, want %v", sum.settings, p.Settings)
				}
			}
			if sum.windowUpdate != p.ConnectionFlow {
				t.Fatalf("connection WINDOW_UPDATE %d, want %d", sum.windowUpdate, p.ConnectionFlow)
			}
			if len(sum.headers) != 6 {
				t.Fatalf("%d HEADERS frames, want 6", len(sum.headers))
			}
			for i, prio := range sum.headers {
				if !sum.headersPrio[i] || prio != p.Priority {
					t.Fatalf("HEADERS priority %+v, want %+v", prio, p.Priority)
				}
			}
		})
	}
}

func TestProfileForFingerprint(t *testing.T) {
	for fp, want := range map[string]*H2Profile{
		"":                Chrome,
		"chrome":          Chrome,
		"hellochrome_152": Chrome,
		"edge":            Chrome,
		"qq":              Chrome,
		"firefox":         Firefox,
		"safari":          nil,
		"ios":             nil,
		"randomized":      nil,
		"unsafe":          nil,
	} {
		if got := ProfileForFingerprint(fp); got != want {
			t.Errorf("%q: got %v, want %v", fp, got, want)
		}
	}
}

type sink struct {
	net.Conn
	buf bytes.Buffer
}

func (s *sink) Write(b []byte) (int, error) { return s.buf.Write(b) }

func (s *sink) Bytes() []byte { return s.buf.Bytes() }

// Frames split at any byte boundary between writes must give the same stream.
func TestConnSplitWrites(t *testing.T) {
	var raw bytes.Buffer
	raw.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&raw, nil)
	fr.WriteSettings(http2.Setting{ID: http2.SettingEnablePush}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384}, http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536})
	fr.WriteWindowUpdate(0, 15663105)
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte("abc"), EndHeaders: true})
	fr.WriteData(1, false, bytes.Repeat([]byte{1}, 1000))
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: []byte("defg"), EndHeaders: true, PadLength: 2})
	fr.WriteData(3, true, bytes.Repeat([]byte{2}, 70000%16384))
	fr.WriteSettingsAck()

	whole := &sink{}
	Chrome.Conn(whole).Write(raw.Bytes())
	split := &sink{}
	c := Chrome.Conn(split)
	for _, b := range raw.Bytes() {
		c.Write([]byte{b})
	}
	if !bytes.Equal(whole.Bytes(), split.Bytes()) {
		t.Fatal("split writes produce a different stream")
	}
	sum := parseClientFrames(t, whole.Bytes())
	if len(sum.headers) != 2 || !sum.headersPrio[0] || !sum.headersPrio[1] || sum.settings[0].ID != http2.SettingHeaderTableSize {
		t.Fatalf("unexpected rewrite: %+v", sum)
	}
	if len(whole.Bytes()) != raw.Len()-6+5+5 {
		t.Fatalf("unexpected length %d of %d", len(whole.Bytes()), raw.Len())
	}
}
