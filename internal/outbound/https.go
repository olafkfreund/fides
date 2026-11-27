// Package outbound enforces the public HTTPS policy for tenant integrations.
package outbound

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ValidateHTTPS checks an endpoint and all its current DNS answers.
func ValidateHTTPS(raw string) error {
	return validateHTTPS(raw, net.DefaultResolver.LookupNetIP)
}

func validateHTTPS(raw string, lookup func(context.Context, string, string) ([]netip.Addr, error)) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("URL must use HTTPS and have a host")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		return checkAddress(ip)
	}
	ips, err := lookup(context.Background(), "ip", u.Hostname())
	if err != nil {
		return fmt.Errorf("host does not resolve: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("host does not resolve to any address")
	}
	for _, ip := range ips {
		if err := checkAddress(ip); err != nil {
			return err
		}
	}
	return nil
}

func checkAddress(ip netip.Addr) error {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("disallowed destination address (%s)", ip)
	}
	return nil
}

// NewHTTPSClient preserves the default transport settings and dials directly
// so the address checked by Control is the actual destination.
func NewHTTPSClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			destination, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("invalid dial address: %w", err)
			}
			return checkAddress(destination.Addr())
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: checkRedirect}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	first := via[0].URL
	if first.Scheme != "https" || req.URL.Scheme != "https" ||
		originHost(first) != originHost(req.URL) || effectivePort(first) != effectivePort(req.URL) {
		return fmt.Errorf("redirect must stay on the initial HTTPS origin")
	}
	return nil
}

func originHost(u *url.URL) string {
	// DNS folds ASCII case. Unicode case folding can equate distinct IDNA names.
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, u.Hostname())
}

func effectivePort(u *url.URL) string {
	if u.Port() == "" {
		return "443"
	}
	return strings.TrimLeft(u.Port(), "0")
}
