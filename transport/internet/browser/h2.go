// Package browser makes Xray's HTTP/2 client connections look like the ones of real browsers.
//
// The HTTP/2 connection preface (the "Akamai fingerprint") is sent right after the TLS handshake:
// the SETTINGS frame (which settings, in which order, with which values), the connection-level
// WINDOW_UPDATE and the priority carried by HEADERS frames. Go's http2 client differs from every
// browser in all three. Values below are taken from github.com/enetx/surf (profiles/*/transport.go).
//
// Values are configured through the regular x/net/http2 knobs, so the client's own flow control
// and HPACK state always match what is announced. Only the layout Go cannot be told about
// (SETTINGS order, settings Go always sends but browsers don't, HEADERS priority) is fixed up
// on the wire by Conn.
package browser

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"strings"

	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/net/http2"
)

// H2Profile describes the HTTP/2 connection preface of a browser.
type H2Profile struct {
	Name string
	// Settings in the order the browser sends them.
	Settings []http2.Setting
	// ConnectionFlow is the increment of the WINDOW_UPDATE on stream 0 sent after SETTINGS.
	ConnectionFlow uint32
	// Priority is put into every HEADERS frame; Weight is the wire value (weight-1).
	Priority http2.PriorityParam
}

// Chrome is Chrome 152 desktop: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p.
var Chrome = &H2Profile{
	Name: "chrome",
	Settings: []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	},
	ConnectionFlow: 15663105,
	Priority:       http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255},
}

// Firefox is Firefox 148 desktop: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s.
var Firefox = &H2Profile{
	Name: "firefox",
	Settings: []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 131072},
		{ID: http2.SettingMaxFrameSize, Val: 16384},
	},
	ConnectionFlow: 12517377,
	Priority:       http2.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 41},
}

// defaults of RFC 9113 section 6.5.2, a setting with its default value may be omitted or added freely.
var settingDefaults = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:   4096,
	http2.SettingInitialWindowSize: 65535,
	http2.SettingMaxFrameSize:      16384,
}

const maxDefaultFrameSize = 16384

// Setting ids whose absence on the wire only lifts a limit the client enforces anyway.
var advisorySettings = map[http2.SettingID]bool{
	http2.SettingMaxHeaderListSize: true,
}

var disabled = strings.ToLower(platform.NewEnvFlag("xray.browser.h2").GetValue(func() string { return "" })) == "off"

// ProfileForFingerprint picks the HTTP/2 profile matching a uTLS fingerprint name as used in
// tlsSettings/realitySettings. It returns nil when the client should keep Go's defaults.
func ProfileForFingerprint(fingerprint string) *H2Profile {
	if disabled {
		return nil
	}
	fingerprint = strings.ToLower(fingerprint)
	switch {
	case fingerprint == "unsafe" || fingerprint == "hellogolang":
		return nil
	case strings.Contains(fingerprint, "firefox"):
		return Firefox
	case strings.Contains(fingerprint, "safari"), strings.Contains(fingerprint, "ios"),
		strings.Contains(fingerprint, "random"), strings.Contains(fingerprint, "android"):
		// no measured profile yet
		return nil
	default:
		// "", chrome*, edge*, qq*, 360*: Chromium
		return Chrome
	}
}

func (p *H2Profile) setting(id http2.SettingID) (uint32, bool) {
	for _, s := range p.Settings {
		if s.ID == id {
			return s.Val, true
		}
	}
	return 0, false
}

// NewTransport returns an http2.Transport whose flow control windows, HPACK table size and
// frame size match the profile. The caller sets DialTLSContext and must wrap the dialed
// connection with p.Conn. A nil profile gives a plain http2.Transport.
func (p *H2Profile) NewTransport() *http2.Transport {
	if p == nil {
		return &http2.Transport{}
	}
	cfg := &http.HTTP2Config{
		MaxReceiveBufferPerConnection: int(p.ConnectionFlow),
		MaxDecoderHeaderTableSize:     4096,
		MaxReadFrameSize:              maxDefaultFrameSize,
	}
	if v, ok := p.setting(http2.SettingInitialWindowSize); ok {
		cfg.MaxReceiveBufferPerStream = int(v)
	}
	if v, ok := p.setting(http2.SettingHeaderTableSize); ok {
		cfg.MaxDecoderHeaderTableSize = int(v)
	}
	if v, ok := p.setting(http2.SettingMaxFrameSize); ok {
		cfg.MaxReadFrameSize = int(v)
	}
	// x/net/http2 takes these knobs only from an http.Transport it is attached to.
	t, err := http2.ConfigureTransports(&http.Transport{HTTP2: cfg})
	if err != nil {
		return &http2.Transport{}
	}
	// ConfigureTransports makes the pool wait for connections from http.Transport, reset it
	// to the regular one that dials with DialTLSContext.
	t.ConnPool = nil
	if v, ok := p.setting(http2.SettingMaxHeaderListSize); ok {
		t.MaxHeaderListSize = v
	}
	return t
}

// NewDialTransport is NewTransport with DialTLSContext set to dial, the connections it returns
// are wrapped with p.Conn.
func (p *H2Profile) NewDialTransport(dial func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)) *http2.Transport {
	t := p.NewTransport()
	t.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		c, err := dial(ctx, network, addr, cfg)
		if err != nil {
			return nil, err
		}
		return p.Conn(c), nil
	}
	return t
}

// Conn rewrites the client side of an HTTP/2 connection created by a transport from
// NewTransport, see the package doc.
func (p *H2Profile) Conn(c net.Conn) net.Conn {
	if p == nil {
		return c
	}
	return &conn{Conn: c, p: p, prefaceLeft: len(http2.ClientPreface)}
}

type conn struct {
	net.Conn
	p *H2Profile

	prefaceLeft  int
	settingsDone bool

	// frame collects either a frame header or a whole frame to be rewritten
	frame []byte
	// pass is the number of payload bytes of the current frame to forward unchanged
	pass int
	out  []byte
}

// Write forwards everything except an incomplete frame that has to be rewritten or an incomplete
// frame header. x/net/http2 always flushes whole frames, so nothing waits for the next write.
// Every call results in at most one write to the underlying connection, as without the wrapper.
func (c *conn) Write(b []byte) (int, error) {
	n := len(b)
	out := c.out[:0]
	for len(b) > 0 {
		switch {
		case c.prefaceLeft > 0:
			k := min(c.prefaceLeft, len(b))
			out = append(out, b[:k]...)
			b, c.prefaceLeft = b[k:], c.prefaceLeft-k
		case c.pass > 0:
			k := min(c.pass, len(b))
			out = append(out, b[:k]...)
			b, c.pass = b[k:], c.pass-k
		case len(c.frame) < 9:
			k := min(9-len(c.frame), len(b))
			c.frame = append(c.frame, b[:k]...)
			b = b[k:]
			if len(c.frame) == 9 && !c.wantsFrame() {
				out = append(out, c.frame...)
				c.pass = c.payloadLen()
				c.frame = c.frame[:0]
			}
		default:
			k := min(9+c.payloadLen()-len(c.frame), len(b))
			c.frame = append(c.frame, b[:k]...)
			b = b[k:]
			if len(c.frame) == 9+c.payloadLen() {
				out = c.rewrite(out)
				c.frame = c.frame[:0]
			}
		}
	}
	c.out = out[:0]
	if len(out) > 0 {
		if _, err := c.Conn.Write(out); err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (c *conn) payloadLen() int {
	return int(c.frame[0])<<16 | int(c.frame[1])<<8 | int(c.frame[2])
}

func (c *conn) wantsFrame() bool {
	switch http2.FrameType(c.frame[3]) {
	case http2.FrameSettings:
		return !c.settingsDone && c.frame[4]&byte(http2.FlagSettingsAck) == 0
	case http2.FrameHeaders:
		return c.frame[4]&byte(http2.FlagHeadersPriority) == 0 && c.payloadLen()+5 <= maxDefaultFrameSize
	}
	return false
}

func (c *conn) rewrite(out []byte) []byte {
	payload := c.frame[9:]
	switch http2.FrameType(c.frame[3]) {
	case http2.FrameSettings:
		c.settingsDone = true
		return appendFrame(out, http2.FrameSettings, c.frame[4], c.frame[5:9], c.settings(payload))
	case http2.FrameHeaders:
		flags := c.frame[4]
		var p []byte
		if flags&byte(http2.FlagHeadersPadded) != 0 {
			p = append(p, payload[0])
			payload = payload[1:]
		}
		dep := c.p.Priority.StreamDep
		if c.p.Priority.Exclusive {
			dep |= 1 << 31
		}
		p = binary.BigEndian.AppendUint32(p, dep)
		p = append(p, c.p.Priority.Weight)
		p = append(p, payload...)
		return appendFrame(out, http2.FrameHeaders, flags|byte(http2.FlagHeadersPriority), c.frame[5:9], p)
	}
	return append(out, c.frame...)
}

// settings lays the client's own settings out in the profile's order. A value Go announced is
// never changed; a profile setting Go did not send is added only with its RFC default value,
// and a Go setting the profile lacks is dropped only when that changes nothing.
func (c *conn) settings(payload []byte) []byte {
	sent := map[http2.SettingID]uint32{}
	var order []http2.SettingID
	for i := 0; i+6 <= len(payload); i += 6 {
		id := http2.SettingID(binary.BigEndian.Uint16(payload[i:]))
		if _, ok := sent[id]; !ok {
			order = append(order, id)
		}
		sent[id] = binary.BigEndian.Uint32(payload[i+2:])
	}
	var p []byte
	add := func(id http2.SettingID, v uint32) {
		p = binary.BigEndian.AppendUint16(p, uint16(id))
		p = binary.BigEndian.AppendUint32(p, v)
	}
	for _, s := range c.p.Settings {
		if v, ok := sent[s.ID]; ok {
			add(s.ID, v)
			delete(sent, s.ID)
		} else if def, ok := settingDefaults[s.ID]; ok && def == s.Val {
			add(s.ID, s.Val)
		}
	}
	for _, id := range order {
		v, ok := sent[id]
		if !ok {
			continue
		}
		if def, known := settingDefaults[id]; (known && def == v) || advisorySettings[id] {
			continue
		}
		add(id, v)
	}
	return p
}

func appendFrame(out []byte, typ http2.FrameType, flags byte, streamID []byte, payload []byte) []byte {
	out = append(out, byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)), byte(typ), flags)
	out = append(out, streamID...)
	return append(out, payload...)
}
