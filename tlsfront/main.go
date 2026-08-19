// tlsfront terminates TLS in front of the sensor, fingerprints the ClientHello
// and forwards the request with the JA4 attached.
//
// Why a separate process: the ClientHello is consumed by the TLS handshake, and
// once Python's ssl module has the socket those bytes are gone. Reading them
// first means reading them before anything else touches the connection.
//
// Standard library only. No module downloads, so `go build` works on a machine
// that has never seen this repo.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

type ctxKey string

const fingerprintKey ctxKey = "ja4"

// Headers the sensor trusts. Anything arriving under these names from the
// client is dropped before proxying, same rule the nginx edge follows.
const (
	headerJA4      = "X-Edge-JA4"
	headerJA4Raw   = "X-Edge-JA4-Raw"
	headerJA4SNI   = "X-Edge-JA4-SNI"
	headerClientIP = "X-Edge-Client-IP"
)

var trustedHeaders = []string{headerJA4, headerJA4Raw, headerJA4SNI, headerClientIP}

// handshakeReadTimeout bounds how long a connection can sit having sent nothing.
// Without it, opening sockets and never speaking is a free way to exhaust the
// listener.
const handshakeReadTimeout = 10 * time.Second

// prefixConn replays bytes that were already read off the wire, so the TLS
// handshake still sees the ClientHello we consumed to fingerprint it.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// fpConn carries the fingerprint alongside the connection so the HTTP handler
// can reach it later.
type fpConn struct {
	net.Conn
	fp Fingerprint
}

type fpListener struct {
	net.Listener
	tlsConfig *tls.Config
}

// readRecord pulls exactly one TLS record: 5 byte header, then the declared
// length. The length is attacker controlled, so it is capped at the protocol
// maximum rather than trusted.
func readRecord(c net.Conn) ([]byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(handshakeReadTimeout)); err != nil {
		return nil, err
	}
	defer c.SetReadDeadline(time.Time{})

	header := make([]byte, 5)
	if _, err := io.ReadFull(c, header); err != nil {
		return nil, err
	}
	length := int(header[3])<<8 | int(header[4])
	if length > 1<<14 {
		return nil, errors.New("oversized TLS record")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func (l *fpListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	record, err := readRecord(raw)
	if err != nil {
		raw.Close()
		// Not an error worth logging per connection: scanners open and drop
		// sockets constantly, and logging each one is how a honeypot fills a
		// disk with its own noise.
		return l.Accept()
	}

	var fp Fingerprint
	if ch, err := ParseClientHello(record); err == nil {
		fp = ch.JA4('t')
	}

	replayed := &prefixConn{Conn: raw, prefix: record}
	return &fpConn{Conn: tls.Server(replayed, l.tlsConfig), fp: fp}, nil
}

// selfSignedCert generates a throwaway certificate at startup. The lab is
// reached by IP over a hostname nobody validates, so shipping a cert generation
// step for the operator to run would be ceremony with no security value.
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "edge-deception-lab"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "portal.example"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func loadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	log.Println("no certificate given, generating a self-signed one")
	return selfSignedCert()
}

func main() {
	listen := flag.String("listen", envOr("EDL_TLS_LISTEN", ":8443"), "TLS listen address")
	upstream := flag.String("upstream", envOr("EDL_UPSTREAM", "http://127.0.0.1:8080"), "sensor base URL")
	certFile := flag.String("cert", os.Getenv("EDL_TLS_CERT"), "certificate file (optional)")
	keyFile := flag.String("key", os.Getenv("EDL_TLS_KEY"), "private key file (optional)")
	flag.Parse()

	target, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("bad upstream: %v", err)
	}

	cert, err := loadCertificate(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	base, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Director = func(r *http.Request) {
		r.URL.Scheme = target.Scheme
		r.URL.Host = target.Host

		// Drop anything the client sent under a trusted name before setting
		// our own. Same reason nginx uses proxy_set_header instead of add.
		for _, h := range trustedHeaders {
			r.Header.Del(h)
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		r.Header.Set(headerClientIP, host)

		if fp, ok := r.Context().Value(fingerprintKey).(Fingerprint); ok && fp.JA4 != "" {
			r.Header.Set(headerJA4, fp.JA4)
			r.Header.Set(headerJA4Raw, fp.JA4Raw)
			if fp.SNI != "" {
				r.Header.Set(headerJA4SNI, fp.SNI)
			}
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Never surface an upstream failure to the client: a distinctive error
		// page is a way to tell this host apart from a real application.
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusBadGateway)
	}

	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if fc, ok := c.(*fpConn); ok {
				return context.WithValue(ctx, fingerprintKey, fc.fp)
			}
			return ctx
		},
	}

	log.Printf("tlsfront listening on %s, forwarding to %s", *listen, target)
	if err := server.Serve(&fpListener{Listener: base, tlsConfig: tlsConfig}); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
