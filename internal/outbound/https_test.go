package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestValidateHTTPS(t *testing.T) {
	for _, tt := range []struct {
		name    string
		answers []string
		wantErr bool
	}{
		{"public", []string{"192.0.2.1", "2001:db8::1"}, false},
		{"mixed", []string{"192.0.2.1", "10.0.0.1"}, true},
		{"loopback", []string{"127.0.0.1"}, true},
		{"mapped loopback", []string{"::ffff:127.0.0.1"}, true},
		{"IPv6 private", []string{"fd00::1"}, true},
		{"link-local unicast", []string{"fe80::1"}, true},
		{"link-local multicast", []string{"ff02::1"}, true},
		{"unspecified", []string{"0.0.0.0"}, true},
		{"empty", nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if network != "ip" || host != "endpoint.test" {
					t.Fatalf("unexpected lookup for %s %s", network, host)
				}
				var ips []netip.Addr
				for _, answer := range tt.answers {
					ips = append(ips, netip.MustParseAddr(answer))
				}
				return ips, nil
			}
			if err := validateHTTPS("https://endpoint.test", lookup); (err != nil) != tt.wantErr {
				t.Fatalf("validateHTTPS returned %v, want error %t", err, tt.wantErr)
			}
		})
	}
	lookupErr := errors.New("fake resolver error")
	if err := validateHTTPS("https://endpoint.test", func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, lookupErr
	}); !errors.Is(err, lookupErr) {
		t.Fatalf("expected resolver error, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestSameOriginHTTP(t *testing.T) {
	base := &url.URL{Scheme: "http", Host: "provider.test"}
	if !SameOrigin(base, &url.URL{Scheme: "http", Host: "PROVIDER.test:080"}) {
		t.Error("HTTP default port and hostname case should match")
	}
	if SameOrigin(base, &url.URL{Scheme: "http", Host: "provider.test:443"}) ||
		SameOrigin(base, &url.URL{Scheme: "https", Host: "provider.test:80"}) {
		t.Error("different ports and schemes should not match")
	}
}

func TestHTTPSRedirects(t *testing.T) {
	for _, tt := range []struct {
		name, start, location string
		wantCalls             int
		wantErr               bool
	}{
		{"relative", "https://endpoint.test/start", "/next", 2, false},
		{"default port", "https://endpoint.test/start", "https://ENDPOINT.test:443/next", 2, false},
		{"numeric port", "https://endpoint.test:00443/start", "https://endpoint.test/next", 2, false},
		{"explicit port", "https://endpoint.test:8443/start", "https://endpoint.test:8443/next", 2, false},
		{"other host", "https://endpoint.test/start", "https://other.test/next", 1, true},
		{"distinct IDNA hosts", "https://σ.test/start", "https://ς.test/next", 1, true},
		{"other port", "https://endpoint.test/start", "https://endpoint.test:8443/next", 1, true},
		{"different scheme", "https://endpoint.test/start", "http://endpoint.test/next", 1, true},
		{"return to start", "https://endpoint.test/start", "/start", 10, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := NewHTTPSClient(0)
			calls := 0
			client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Path == "/start" {
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {tt.location}}, Body: http.NoBody}, nil
				}
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			})
			resp, err := client.Get(tt.start)
			if err == nil {
				resp.Body.Close()
			}
			if (err != nil) != tt.wantErr || calls != tt.wantCalls {
				t.Fatalf("got %d requests and error %v, want %d requests and error %t", calls, err, tt.wantCalls, tt.wantErr)
			}
		})
	}
}

func TestHTTPSClientRejectsResolvedLoopback(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	client := NewHTTPSClient(0)
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("expected direct transport")
	}
	conn, err := transport.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err == nil {
		conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "disallowed destination address") {
		t.Fatalf("expected dial guard to reject loopback, got %v", err)
	}
}
