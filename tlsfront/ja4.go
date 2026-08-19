// JA4 TLS client fingerprinting.
//
// JA4 (the TLS client fingerprint) is BSD-3 licensed by FoxIO. The rest of the
// JA4+ suite (JA4S, JA4H, JA4L and so on) is under FoxIO License 1.1, which
// restricts monetization, so none of it is implemented here.
//
// Spec: https://github.com/FoxIO-LLC/ja4
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	recordHandshake  = 0x16
	handshakeHello   = 0x01
	extServerName    = 0x0000
	extALPN          = 0x0010
	extSigAlgs       = 0x000d
	extSupportedVers = 0x002b
)

var errNotClientHello = errors.New("not a TLS ClientHello")

// ClientHello holds only the fields JA4 needs.
type ClientHello struct {
	LegacyVersion     uint16
	SupportedVersions []uint16
	CipherSuites      []uint16
	Extensions        []uint16
	SignatureAlgs     []uint16
	ALPNProtocols     []string
	HasSNI            bool
	ServerName        string
}

// isGREASE reports whether a value is one of the reserved GREASE points
// (0x0a0a, 0x1a1a ... 0xfafa). Clients inject them at random to keep middleboxes
// honest, so they have to come out before anything is counted or hashed.
func isGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v & 0xff)
	return hi == lo && lo&0x0f == 0x0a
}

type reader struct {
	buf []byte
	pos int
}

func (r *reader) u8() (uint8, error) {
	if r.pos+1 > len(r.buf) {
		return 0, errNotClientHello
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.pos+2 > len(r.buf) {
		return 0, errNotClientHello
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, errNotClientHello
	}
	v := r.buf[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

// ParseClientHello accepts a full TLS record (5 byte header included) and pulls
// out the JA4 inputs. It does not validate anything it does not need: this runs
// against hostile traffic, so it fails closed on short reads instead of trusting
// declared lengths.
func ParseClientHello(record []byte) (*ClientHello, error) {
	if len(record) < 9 || record[0] != recordHandshake {
		return nil, errNotClientHello
	}

	r := &reader{buf: record, pos: 5}

	msgType, err := r.u8()
	if err != nil || msgType != handshakeHello {
		return nil, errNotClientHello
	}
	if _, err := r.bytes(3); err != nil { // handshake length
		return nil, err
	}

	ch := &ClientHello{}
	if ch.LegacyVersion, err = r.u16(); err != nil {
		return nil, err
	}
	if _, err := r.bytes(32); err != nil { // random
		return nil, err
	}

	sessionLen, err := r.u8()
	if err != nil {
		return nil, err
	}
	if _, err := r.bytes(int(sessionLen)); err != nil {
		return nil, err
	}

	cipherLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	cipherBytes, err := r.bytes(int(cipherLen))
	if err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(cipherBytes); i += 2 {
		v := binary.BigEndian.Uint16(cipherBytes[i:])
		if !isGREASE(v) {
			ch.CipherSuites = append(ch.CipherSuites, v)
		}
	}

	compLen, err := r.u8()
	if err != nil {
		return nil, err
	}
	if _, err := r.bytes(int(compLen)); err != nil {
		return nil, err
	}

	// Extensions are optional in the wire format, so running out here is a
	// valid hello rather than an error.
	extTotal, err := r.u16()
	if err != nil {
		return ch, nil
	}
	extBytes, err := r.bytes(int(extTotal))
	if err != nil {
		return nil, err
	}

	er := &reader{buf: extBytes}
	for er.pos < len(er.buf) {
		extType, err := er.u16()
		if err != nil {
			break
		}
		extLen, err := er.u16()
		if err != nil {
			break
		}
		body, err := er.bytes(int(extLen))
		if err != nil {
			break
		}
		if isGREASE(extType) {
			continue
		}
		ch.Extensions = append(ch.Extensions, extType)

		switch extType {
		case extServerName:
			ch.HasSNI = true
			ch.ServerName = parseSNI(body)
		case extALPN:
			ch.ALPNProtocols = parseALPN(body)
		case extSigAlgs:
			ch.SignatureAlgs = parseU16List(body)
		case extSupportedVers:
			ch.SupportedVersions = parseSupportedVersions(body)
		}
	}

	return ch, nil
}

func parseSNI(body []byte) string {
	if len(body) < 5 {
		return ""
	}
	// list length (2) + name type (1) + name length (2)
	nameLen := int(binary.BigEndian.Uint16(body[3:]))
	if 5+nameLen > len(body) {
		return ""
	}
	return string(body[5 : 5+nameLen])
}

func parseALPN(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	var out []string
	r := &reader{buf: body, pos: 2}
	for r.pos < len(r.buf) {
		n, err := r.u8()
		if err != nil {
			break
		}
		v, err := r.bytes(int(n))
		if err != nil {
			break
		}
		out = append(out, string(v))
	}
	return out
}

func parseU16List(body []byte) []uint16 {
	if len(body) < 2 {
		return nil
	}
	var out []uint16
	for i := 2; i+1 < len(body); i += 2 {
		v := binary.BigEndian.Uint16(body[i:])
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func parseSupportedVersions(body []byte) []uint16 {
	if len(body) < 1 {
		return nil
	}
	n := int(body[0])
	var out []uint16
	for i := 1; i+1 < len(body) && i < 1+n; i += 2 {
		v := binary.BigEndian.Uint16(body[i:])
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// versionString maps a TLS version to its two character JA4 form.
func versionString(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0200:
		return "s2"
	case 0x0100:
		return "s1"
	default:
		return "00"
	}
}

// negotiatedVersion prefers the supported_versions extension. TLS 1.3 pins
// legacy_version at 1.2 for compatibility, so reading the legacy field alone
// would label every modern client as 1.2.
func (ch *ClientHello) negotiatedVersion() uint16 {
	var best uint16
	for _, v := range ch.SupportedVersions {
		if v > best {
			best = v
		}
	}
	if best != 0 {
		return best
	}
	return ch.LegacyVersion
}

func twoDigits(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// alpnCode is the first and last character of the first ALPN value. Non
// alphanumeric bytes fall back to hex so the field stays two printable chars.
func (ch *ClientHello) alpnCode() string {
	if len(ch.ALPNProtocols) == 0 || ch.ALPNProtocols[0] == "" {
		return "00"
	}
	v := ch.ALPNProtocols[0]
	first, last := v[0], v[len(v)-1]
	if !isAlnum(first) || !isAlnum(last) {
		h := hex.EncodeToString([]byte{first, last})
		return string(h[0]) + string(h[len(h)-1])
	}
	return string(first) + string(last)
}

func hexList(values []uint16) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, fmt.Sprintf("%04x", v))
	}
	return out
}

func truncatedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// Fingerprint is the JA4 of a hello, with the raw form kept alongside it.
// JA4_r is what you read when a hash does not match anything and you need to
// see which cipher or extension actually moved.
type Fingerprint struct {
	JA4    string `json:"ja4"`
	JA4Raw string `json:"ja4_r"`
	SNI    string `json:"sni,omitempty"`
	ALPN   string `json:"alpn,omitempty"`
}

// JA4 builds the fingerprint: transport, version, SNI presence, cipher and
// extension counts, ALPN, then a hash of the sorted ciphers and a hash of the
// sorted extensions plus signature algorithms.
func (ch *ClientHello) JA4(transport byte) Fingerprint {
	sniFlag := "i"
	if ch.HasSNI {
		sniFlag = "d"
	}

	partA := fmt.Sprintf("%c%s%s%s%s%s",
		transport,
		versionString(ch.negotiatedVersion()),
		sniFlag,
		twoDigits(len(ch.CipherSuites)),
		twoDigits(len(ch.Extensions)),
		ch.alpnCode(),
	)

	ciphers := hexList(ch.CipherSuites)
	sort.Strings(ciphers)
	cipherList := strings.Join(ciphers, ",")

	// SNI and ALPN are already represented in part A, so they come out of the
	// extension hash. Sorting the rest makes the fingerprint survive clients
	// that shuffle extension order between connections.
	var filtered []uint16
	for _, e := range ch.Extensions {
		if e == extServerName || e == extALPN {
			continue
		}
		filtered = append(filtered, e)
	}
	exts := hexList(filtered)
	sort.Strings(exts)
	extList := strings.Join(exts, ",")

	sigList := strings.Join(hexList(ch.SignatureAlgs), ",")
	extAndSigs := extList
	if sigList != "" {
		extAndSigs = extList + "_" + sigList
	}

	partB := "000000000000"
	if cipherList != "" {
		partB = truncatedSHA256(cipherList)
	}
	partC := "000000000000"
	if extList != "" {
		partC = truncatedSHA256(extAndSigs)
	}

	alpn := ""
	if len(ch.ALPNProtocols) > 0 {
		alpn = ch.ALPNProtocols[0]
	}

	return Fingerprint{
		JA4:    fmt.Sprintf("%s_%s_%s", partA, partB, partC),
		JA4Raw: fmt.Sprintf("%s_%s_%s", partA, cipherList, extAndSigs),
		SNI:    ch.ServerName,
		ALPN:   alpn,
	}
}
