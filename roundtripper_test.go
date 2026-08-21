package tls_client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/bandwidth"
	"github.com/bogdanfinn/tls-client/profiles"
	"golang.org/x/net/proxy"
)

// generateSelfSignedCert creates an ephemeral, in-memory certificate for
// 127.0.0.1 so tests can stand up a local TLS server without touching disk.
func generateSelfSignedCert(t *testing.T) stdtls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// startAlternatingALPNServer starts a TLS server that negotiates
// "http/1.1" on its first accepted connection and "h2" on every connection
// after that, mimicking a backend that changes ALPN behavior between
// connections to the same address. It never speaks either protocol on the
// wire - the tests only care about the negotiated ClientHello/ServerHello
// result, since that's all roundTripper.dialTLS inspects.
func startAlternatingALPNServer(t *testing.T) net.Listener {
	t.Helper()

	cert := generateSelfSignedCert(t)

	var connCount int32

	cfg := &stdtls.Config{
		GetConfigForClient: func(*stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			protos := []string{"http/1.1"}
			if atomic.AddInt32(&connCount, 1) > 1 {
				protos = []string{"h2"}
			}
			return &stdtls.Config{Certificates: []stdtls.Certificate{cert}, NextProtos: protos}, nil
		},
	}

	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*stdtls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()

	return ln
}

// TestDialTLS_RebuildsTransportOnProtocolChange guards against a regression
// of https://github.com/bogdanfinn/tls-client/issues/263: dialTLS used to
// return a freshly dialed connection straight to the caller whenever
// cachedTransports[addr] was already populated, without checking that the
// newly negotiated ALPN protocol still matched the cached transport. If a
// server switched protocols between connections to the same address (e.g.
// HTTP/1.1 -> HTTP/2), the stale transport kept being reused and fed frames
// it couldn't parse, permanently breaking that address until the client was
// replaced.
func TestDialTLS_RebuildsTransportOnProtocolChange(t *testing.T) {
	ln := startAlternatingALPNServer(t)
	addr := ln.Addr().String()

	rtIface, err := newRoundTripper(profiles.Chrome_133, nil, "", true, false, false, true, false, nil, nil, false, false, bandwidth.NewNopeTracker(), proxy.Direct)
	if err != nil {
		t.Fatalf("newRoundTripper: %v", err)
	}
	rt := rtIface.(*roundTripper)

	ctx := context.Background()

	// Dial 1: negotiates HTTP/1.1 and caches an *http.Transport for addr.
	if _, err = rt.dialTLS(ctx, "tcp", addr); err != errProtocolNegotiated {
		t.Fatalf("dial 1: expected errProtocolNegotiated, got %v", err)
	}
	if got := rt.cachedProtocols[addr]; got != "http/1.1" {
		t.Fatalf("dial 1: expected cached protocol http/1.1, got %q", got)
	}
	if _, ok := rt.cachedTransports[addr].(*http.Transport); !ok {
		t.Fatalf("dial 1: expected *http.Transport, got %T", rt.cachedTransports[addr])
	}

	// In production, the connection stashed by dial 1 is handed off to and
	// consumed by that freshly built transport's first real request. Drop it
	// here to simulate that handoff and force dial 2 to open a genuinely new
	// connection instead of replaying the cached one.
	delete(rt.cachedConnections, addr)

	// Dial 2: the server now negotiates h2 for the same addr. The stale
	// HTTP/1.1 transport must be evicted and rebuilt as *http2.Transport
	// rather than silently reused.
	if _, err = rt.dialTLS(ctx, "tcp", addr); err != errProtocolNegotiated {
		t.Fatalf("dial 2: expected errProtocolNegotiated (transport rebuilt), got %v", err)
	}
	if got := rt.cachedProtocols[addr]; got != http2.NextProtoTLS {
		t.Fatalf("dial 2: expected cached protocol %q, got %q", http2.NextProtoTLS, got)
	}
	if _, ok := rt.cachedTransports[addr].(*http2.Transport); !ok {
		t.Fatalf("dial 2: expected *http2.Transport after protocol change, got %T", rt.cachedTransports[addr])
	}

	delete(rt.cachedConnections, addr)

	// Dial 3: still h2, matching the now-cached transport, so it must be
	// reused as-is with no error and no rebuild.
	cachedTransport := rt.cachedTransports[addr]
	if _, err = rt.dialTLS(ctx, "tcp", addr); err != nil {
		t.Fatalf("dial 3: expected reused transport with nil error, got %v", err)
	}
	if rt.cachedTransports[addr] != cachedTransport {
		t.Fatalf("dial 3: expected the h2 transport instance to be reused, got a different instance")
	}
}
