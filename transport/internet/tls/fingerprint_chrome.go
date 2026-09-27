package tls

import (
	"crypto/rand"

	utls "github.com/refraction-networking/utls"
)

// Chrome 152 ClientHello, ported from github.com/enetx/surf (MIT, profiles/chrome/tls.go).
//
// uTLS ships HelloChrome_133 as its newest Chrome parrot. Its JA4 (t13d1516h2_8daaf6152771_d8a2da3f94cd)
// is what Chrome sent up to ~v141, so in 2026 it is mostly produced by proxy clients, not browsers.
// Chrome 152 differs from it in three ways, all reproduced here:
//   - signature_algorithms starts with a GREASE value followed by ML-DSA-44/65/87;
//   - the trust_anchors extension (0xca34) with Chrome Root Store trust anchor IDs is always present;
//   - the extension order is re-shuffled on every connection (as since Chrome 110).
// The result is JA4 t13d1517h2_8daaf6152771_* and a byte-for-byte Chrome 152 layout
// (sizes vary only with the GREASE ECH payload, like in real Chrome).

// ML-DSA signature schemes Chrome 152 advertises; uTLS does not name them yet.
const (
	sigSchemeMLDSA44 utls.SignatureScheme = 0x0904
	sigSchemeMLDSA65 utls.SignatureScheme = 0x0905
	sigSchemeMLDSA87 utls.SignatureScheme = 0x0906
)

// extensionTrustAnchors is the TLS Trust Anchor Identifiers extension (draft-ietf-tls-trust-anchor-ids).
const extensionTrustAnchors uint16 = 0xca34

// chrome152TrustAnchorIDs is the trust_anchors body of a Google Chrome 152.0.7977 desktop ClientHello,
// captured verbatim by surf. The order is a compile-time constant of a Chrome build (it follows the
// compiled-in root store), so it must not be shuffled.
var chrome152TrustAnchorIDs = []byte{
	0x00, 0xcc,
	0x04, 0xd6, 0x79, 0x09, 0x06,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07,
	0x04, 0xd6, 0x79, 0x09, 0x0c,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x06,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x13,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d,
	0x04, 0xd6, 0x79, 0x09, 0x01,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x0d,
	0x04, 0xd6, 0x79, 0x09, 0x0d,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x12,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09,
	0x04, 0xd6, 0x79, 0x09, 0x02,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x01,
	0x04, 0xd6, 0x79, 0x09, 0x0e,
	0x04, 0xd6, 0x79, 0x09, 0x09,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a,
	0x04, 0xd6, 0x79, 0x09, 0x03,
	0x04, 0xd6, 0x79, 0x09, 0x0f,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b,
	0x04, 0xd6, 0x79, 0x09, 0x04,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x14,
	0x04, 0xd6, 0x79, 0x09, 0x0a,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12,
	0x04, 0xd6, 0x79, 0x09, 0x07,
	0x04, 0xd6, 0x79, 0x09, 0x08,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c,
	0x04, 0xd6, 0x79, 0x09, 0x05,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e,
	0x04, 0xd6, 0x79, 0x09, 0x0b,
}

// HelloChrome_152 is served by Xray itself (see NewUConn), uTLS does not know it.
var HelloChrome_152 = utls.ClientHelloID{Client: "Chrome", Version: "152"}

// chrome152Spec returns a fresh Chrome 152 spec. It must be called once per connection:
// the extension order and the GREASE signature scheme are per-connection random, and uTLS
// mutates extension structs while building the hello.
func chrome152Spec() (*utls.ClientHelloSpec, error) {
	return &utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions: utls.ShuffleChromeTLSExtensions([]utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				// BoringSSL takes it from its own GREASE index, uTLS leaves sigalgs alone
				utls.SignatureScheme(randomGREASE()),
				sigSchemeMLDSA44,
				sigSchemeMLDSA65,
				sigSchemeMLDSA87,
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
			&utls.GenericExtension{Id: extensionTrustAnchors, Data: chrome152TrustAnchorIDs},
			utls.BoringGREASEECH(),
			&utls.UtlsGREASEExtension{},
			// No pre_shared_key: Xray never resumes sessions, and Chrome omits it on a full handshake.
		}),
	}, nil
}

// randomGREASE returns one of the 16 GREASE code points (0x0a0a, 0x1a1a, ... 0xfafa).
func randomGREASE() uint16 {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return utls.GREASE_PLACEHOLDER
	}
	return 0x0a0a + 0x1010*uint16(b[0]&0x0f)
}
