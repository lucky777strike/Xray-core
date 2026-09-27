package tls_test

import (
	"context"
	"crypto/sha256"
	gotls "crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

type parsedHello struct {
	ciphers    []uint16
	extensions []uint16
	sigalgs    []uint16
	alpn       []string
}

func parseHello(t *testing.T, raw []byte) parsedHello {
	t.Helper()
	var h parsedHello
	p := 4 + 2 + 32 // handshake header, legacy_version, random
	p += 1 + int(raw[p])
	n := int(binary.BigEndian.Uint16(raw[p:]))
	for i := 0; i < n; i += 2 {
		h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(raw[p+2+i:]))
	}
	p += 2 + n
	p += 1 + int(raw[p])
	end := p + 2 + int(binary.BigEndian.Uint16(raw[p:]))
	p += 2
	for p < end {
		typ := binary.BigEndian.Uint16(raw[p:])
		body := raw[p+4 : p+4+int(binary.BigEndian.Uint16(raw[p+2:]))]
		h.extensions = append(h.extensions, typ)
		switch typ {
		case 13:
			for i := 2; i < len(body); i += 2 {
				h.sigalgs = append(h.sigalgs, binary.BigEndian.Uint16(body[i:]))
			}
		case 16:
			for i := 2; i < len(body); i += 1 + int(body[i]) {
				h.alpn = append(h.alpn, string(body[i+1:i+1+int(body[i])]))
			}
		}
		p += 4 + len(body)
	}
	return h
}

func hexList(v []uint16) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(s, ",")
}

func ja4(h parsedHello) string {
	ciphers := slices.DeleteFunc(slices.Clone(h.ciphers), isGREASE)
	exts := slices.DeleteFunc(slices.Clone(h.extensions), isGREASE)
	a := fmt.Sprintf("t13d%02d%02d%c%c", len(ciphers), len(exts), h.alpn[0][0], h.alpn[0][len(h.alpn[0])-1])
	slices.Sort(ciphers)
	b := sha256.Sum256([]byte(hexList(ciphers)))
	exts = slices.DeleteFunc(exts, func(e uint16) bool { return e == 0 || e == 16 })
	slices.Sort(exts)
	c := sha256.Sum256([]byte(hexList(exts) + "_" + hexList(slices.DeleteFunc(slices.Clone(h.sigalgs), isGREASE))))
	return a + "_" + hex.EncodeToString(b[:6]) + "_" + hex.EncodeToString(c[:6])
}

func buildHello(t *testing.T, name string) parsedHello {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	uConn, err := NewUConn(c1, &utls.Config{ServerName: "www.example.com"}, GetFingerprint(name))
	common.Must(err)
	common.Must(uConn.BuildHandshakeState())
	return parseHello(t, uConn.HandshakeState.Hello.Raw)
}

func TestChrome152Hello(t *testing.T) {
	for _, name := range []string{"", "chrome", "hellochrome_152"} {
		if *GetFingerprint(name) != HelloChrome_152 {
			t.Fatalf("fingerprint %q is not Chrome 152", name)
		}
	}

	orders := map[string]bool{}
	for i := 0; i < 20; i++ {
		h := buildHello(t, "chrome")
		if got := ja4(h); !strings.HasPrefix(got, "t13d1517h2_8daaf6152771_") {
			t.Fatalf("unexpected JA4 %s", got)
		}
		if !isGREASE(h.extensions[0]) || !isGREASE(h.extensions[len(h.extensions)-1]) {
			t.Fatalf("GREASE extensions must stay first and last: %04x", h.extensions)
		}
		if !slices.Contains(h.extensions, 0xca34) || !slices.Contains(h.extensions, 0xfe0d) {
			t.Fatalf("trust_anchors or GREASE ECH missing: %04x", h.extensions)
		}
		if !isGREASE(h.sigalgs[0]) || !slices.Equal(h.sigalgs[1:4], []uint16{0x0904, 0x0905, 0x0906}) {
			t.Fatalf("unexpected sigalgs: %04x", h.sigalgs)
		}
		orders[hexList(h.extensions[1:len(h.extensions)-1])] = true
	}
	if len(orders) < 10 {
		t.Fatalf("extension order is not shuffled per connection: %d distinct orders of 20", len(orders))
	}
	t.Log("JA4:", ja4(buildHello(t, "chrome")))

	if got := ja4(buildHello(t, "hellochrome_133")); got != "t13d1516h2_8daaf6152771_d8a2da3f94cd" {
		t.Fatalf("hellochrome_133 changed: %s", got)
	}
}

func TestChrome152Handshake(t *testing.T) {
	generated, _ := cert.MustGenerate(nil, cert.DNSNames("www.example.com"))
	certificate, err := gotls.X509KeyPair(generated.ToPEM())
	common.Must(err)
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{certificate},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	common.Must(err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 5)
				if _, err := conn.Read(buf); err == nil {
					conn.Write(buf)
				}
			}()
		}
	}()

	for i := 0; i < 10; i++ {
		raw, err := net.Dial("tcp", ln.Addr().String())
		common.Must(err)
		conn := UClient(raw, &gotls.Config{ServerName: "www.example.com", InsecureSkipVerify: true}, GetFingerprint("chrome")).(*UConn)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := conn.HandshakeContext(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
		if state := conn.ConnectionState(); state.Version != gotls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
			t.Fatalf("unexpected state: version %x, alpn %q", state.Version, state.NegotiatedProtocol)
		}
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 5)
		if _, err := conn.Read(buf); err != nil || string(buf) != "hello" {
			t.Fatal("echo failed: ", err)
		}
		conn.Close()
	}
}
