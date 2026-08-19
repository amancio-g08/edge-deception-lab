package main

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// loadFixtures reads the captured ClientHellos. They came off real clients on a
// real socket, so they carry the quirks a hand written test vector would miss.
func loadFixtures(t *testing.T) map[string][]byte {
	t.Helper()
	f, err := os.Open("testdata/clienthellos.txt")
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	defer f.Close()

	out := map[string][]byte{}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			t.Fatalf("bad fixture line: %.40s", line)
		}
		raw, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("%s: %v", parts[0], err)
		}
		out[parts[0]] = raw
	}
	return out
}

// Pinned values. These were produced by this implementation from the captured
// hellos, not by FoxIO's reference tool, so they lock in behaviour rather than
// certify correctness. See the note in README before treating them as canonical.
func TestFingerprintsAreStable(t *testing.T) {
	want := map[string]string{
		"curl-openssl":   "t13i3111h2_e8f1e7e78f70_b26ce05bbdd6",
		"python-ssl":     "t13d181100_85036bcba153_d41ae481755e",
		"openssl-sni":    "t13d311000_e8f1e7e78f70_1f22a2ca17c4",
		"openssl-no-sni": "t13i310900_e8f1e7e78f70_1f22a2ca17c4",
		"chromium":       "t13i1515h2_8daaf6152771_d8a2da3f94cd",
	}

	fixtures := loadFixtures(t)
	for name, expected := range want {
		raw, ok := fixtures[name]
		if !ok {
			t.Fatalf("missing fixture %q", name)
		}
		ch, err := ParseClientHello(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := ch.JA4('t').JA4
		if got != expected {
			t.Errorf("%s\n got %s\nwant %s", name, got, expected)
		}
	}
}

// The point of TLS fingerprinting: two tools that share a TLS stack are the
// same client on the wire, and a browser is not.
func TestSameStackSharesCipherHash(t *testing.T) {
	fixtures := loadFixtures(t)

	cipherHash := func(name string) string {
		ch, err := ParseClientHello(fixtures[name])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return strings.Split(ch.JA4('t').JA4, "_")[1]
	}

	curl := cipherHash("curl-openssl")
	ossl := cipherHash("openssl-sni")
	chrome := cipherHash("chromium")

	if curl != ossl {
		t.Errorf("curl and openssl share a TLS stack, cipher hash should match: %s vs %s", curl, ossl)
	}
	if chrome == curl {
		t.Errorf("chromium should not share a cipher hash with openssl clients")
	}
}

// Chromium is the reason GREASE handling has to be right: it injects reserved
// values into ciphers, extensions and supported_versions on every connection.
func TestGREASEIsStrippedFromChromium(t *testing.T) {
	fixtures := loadFixtures(t)
	ch, err := ParseClientHello(fixtures["chromium"])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range ch.CipherSuites {
		if isGREASE(c) {
			t.Errorf("GREASE cipher survived: %04x", c)
		}
	}
	for _, e := range ch.Extensions {
		if isGREASE(e) {
			t.Errorf("GREASE extension survived: %04x", e)
		}
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x8a8a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%04x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0000, 0x002b, 0xc02f, 0x0a0b, 0x1a2a} {
		if isGREASE(v) {
			t.Errorf("%04x should not be GREASE", v)
		}
	}
}

// TLS 1.3 pins legacy_version at 0x0303 for middlebox compatibility. Reading it
// directly would report every modern client as TLS 1.2.
func TestSupportedVersionsBeatsLegacyVersion(t *testing.T) {
	ch := &ClientHello{
		LegacyVersion:     0x0303,
		SupportedVersions: []uint16{0x0304, 0x0303},
	}
	if got := versionString(ch.negotiatedVersion()); got != "13" {
		t.Errorf("got %q, want 13", got)
	}

	legacyOnly := &ClientHello{LegacyVersion: 0x0303}
	if got := versionString(legacyOnly.negotiatedVersion()); got != "12" {
		t.Errorf("got %q, want 12", got)
	}
}

func TestALPNCode(t *testing.T) {
	cases := []struct {
		protocols []string
		want      string
	}{
		{nil, "00"},
		{[]string{}, "00"},
		{[]string{"h2"}, "h2"},
		{[]string{"http/1.1"}, "h1"},
		{[]string{"h2", "http/1.1"}, "h2"},
		{[]string{"h3"}, "h3"},
		{[]string{"x"}, "xx"},
		{[]string{""}, "00"},
	}
	for _, c := range cases {
		ch := &ClientHello{ALPNProtocols: c.protocols}
		if got := ch.alpnCode(); got != c.want {
			t.Errorf("%v: got %q, want %q", c.protocols, got, c.want)
		}
	}
}

func TestSNIFlagAndServerName(t *testing.T) {
	fixtures := loadFixtures(t)

	withSNI, err := ParseClientHello(fixtures["openssl-sni"])
	if err != nil {
		t.Fatal(err)
	}
	if !withSNI.HasSNI || withSNI.ServerName != "portal.example" {
		t.Errorf("expected SNI portal.example, got %q (has=%v)", withSNI.ServerName, withSNI.HasSNI)
	}
	if ja4 := withSNI.JA4('t').JA4; ja4[3] != 'd' {
		t.Errorf("SNI present should give 'd', got %c", ja4[3])
	}

	noSNI, err := ParseClientHello(fixtures["openssl-no-sni"])
	if err != nil {
		t.Fatal(err)
	}
	if noSNI.HasSNI {
		t.Error("did not expect SNI")
	}
	if ja4 := noSNI.JA4('t').JA4; ja4[3] != 'i' {
		t.Errorf("no SNI should give 'i', got %c", ja4[3])
	}
}

// SNI and ALPN are already encoded in part a, so they must not also land in the
// extension hash. Same client with and without SNI keeps the same part c.
func TestSNIAndALPNExcludedFromExtensionHash(t *testing.T) {
	fixtures := loadFixtures(t)

	withSNI, _ := ParseClientHello(fixtures["openssl-sni"])
	noSNI, _ := ParseClientHello(fixtures["openssl-no-sni"])

	a := strings.Split(withSNI.JA4('t').JA4, "_")[2]
	b := strings.Split(noSNI.JA4('t').JA4, "_")[2]
	if a != b {
		t.Errorf("extension hash changed with SNI alone: %s vs %s", a, b)
	}
}

func TestCountsAreCappedAtTwoDigits(t *testing.T) {
	many := make([]uint16, 150)
	for i := range many {
		many[i] = uint16(0x1300 + i)
	}
	ch := &ClientHello{LegacyVersion: 0x0303, CipherSuites: many, Extensions: many}
	ja4 := ch.JA4('t').JA4
	if ja4[4:6] != "99" || ja4[6:8] != "99" {
		t.Errorf("counts should cap at 99, got %s", ja4[:10])
	}
}

func TestEmptyListsUseZeroHash(t *testing.T) {
	ch := &ClientHello{LegacyVersion: 0x0303}
	parts := strings.Split(ch.JA4('t').JA4, "_")
	if parts[1] != "000000000000" || parts[2] != "000000000000" {
		t.Errorf("empty lists should hash to zeros, got %v", parts)
	}
}

func TestRawFingerprintSharesPartA(t *testing.T) {
	fixtures := loadFixtures(t)
	ch, err := ParseClientHello(fixtures["chromium"])
	if err != nil {
		t.Fatal(err)
	}
	fp := ch.JA4('t')
	if strings.Split(fp.JA4, "_")[0] != strings.Split(fp.JA4Raw, "_")[0] {
		t.Error("JA4 and JA4_r must agree on part a")
	}
	if !strings.Contains(fp.JA4Raw, ",") {
		t.Error("raw form should list values, not hash them")
	}
}

// The parser runs first, on bytes chosen by whoever connected. Truncation and
// garbage have to come back as errors, never as a panic.
func TestMalformedInputNeverPanics(t *testing.T) {
	fixtures := loadFixtures(t)
	full := fixtures["chromium"]

	for i := 0; i < len(full); i++ {
		if _, err := ParseClientHello(full[:i]); err == nil {
			// A prefix may still parse if extensions happen to end cleanly.
			continue
		}
	}

	garbage := [][]byte{
		nil,
		{},
		{0x16},
		{0x16, 0x03, 0x01, 0xff, 0xff},
		{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5},
		make([]byte, 4096),
	}
	for i, g := range garbage {
		if _, err := ParseClientHello(g); err == nil && len(g) < 10 {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestNonHandshakeRecordIsRejected(t *testing.T) {
	// Application data record, not a handshake.
	record := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}
	if _, err := ParseClientHello(record); err == nil {
		t.Error("expected an error for a non-handshake record")
	}
}
