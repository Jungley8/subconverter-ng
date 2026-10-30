package fetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrBlockedIP indicates an IP address was blocked by SSRF defense.
	ErrBlockedIP = errors.New("SSRF protection: connection to private/loopback IP address blocked")
	// ErrBlockedRedirect indicates a redirect target was blocked by SSRF defense.
	ErrBlockedRedirect = errors.New("SSRF protection: redirect to private/loopback address blocked")
)

// isBlockedIP reports whether ip is a private, loopback, link-local, multicast,
// unspecified, or carrier-grade NAT address.
func isBlockedIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return true
	}
	// Carrier-Grade NAT (CGNAT) RFC 6598: 100.64.0.0/10
	cgnat := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)
	if cgnat.Contains(addr) {
		return true
	}
	// Documentation / test ranges
	testnet1 := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 24)
	testnet2 := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, 0}), 24)
	testnet3 := netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, 0}), 24)
	if testnet1.Contains(addr) || testnet2.Contains(addr) || testnet3.Contains(addr) {
		return true
	}
	return false
}

// validateTargetURL validates a target URL string against SSRF before dialing.
func validateTargetURL(raw string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (only http and https allowed)", scheme)
	}
	hostname := u.Hostname()
	if hostname == "" {
		return errors.New("missing host in URL")
	}
	if strings.EqualFold(hostname, "localhost") {
		return ErrBlockedIP
	}
	// If hostname is directly an IP literal
	if ip, err := netip.ParseAddr(hostname); err == nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedIP, ip)
		}
	}
	return nil
}

// safeDialContext creates a DialContext function that blocks private/loopback IPs
// and dials directly to the resolved IP to prevent DNS rebinding attacks.
func safeDialContext(dialer *net.Dialer, allowPrivate bool, proxyHost string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// When allowPrivate is true or dialing the operator's explicitly configured proxy host, allow direct dial.
		if allowPrivate || (proxyHost != "" && strings.EqualFold(host, proxyHost)) {
			return dialer.DialContext(ctx, network, addr)
		}

		// Check if host is already an IP address
		if ip, err := netip.ParseAddr(host); err == nil {
			if isBlockedIP(ip) {
				return nil, fmt.Errorf("%w: %s", ErrBlockedIP, ip)
			}
			return dialer.DialContext(ctx, network, addr)
		}

		// Resolve host IPs
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP address found for %s", host)
		}

		// Fail closed: if ANY resolved IP is blocked, reject the request (anti-rebinding / multihomed bypass)
		for _, ip := range ips {
			if isBlockedIP(ip) {
				return nil, fmt.Errorf("%w: %s resolves to %s", ErrBlockedIP, host, ip)
			}
		}

		// Connect directly to the first validated IP address to prevent DNS rebinding TOCTOU
		targetAddr := net.JoinHostPort(ips[0].String(), port)
		return dialer.DialContext(ctx, network, targetAddr)
	}
}

// safeCheckRedirect returns a CheckRedirect function that blocks redirects to private/loopback addresses.
func safeCheckRedirect(allowPrivate bool) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if allowPrivate {
			return nil
		}
		u := req.URL
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("%w: unsupported scheme %s", ErrBlockedRedirect, scheme)
		}
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return fmt.Errorf("%w: localhost", ErrBlockedRedirect)
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if isBlockedIP(ip) {
				return fmt.Errorf("%w: %s", ErrBlockedRedirect, ip)
			}
			return nil
		}
		// Resolve domain to ensure redirect does not rebind or target internal services
		ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return fmt.Errorf("redirect DNS lookup: %w", err)
		}
		for _, ip := range ips {
			if isBlockedIP(ip) {
				return fmt.Errorf("%w: %s resolves to %s", ErrBlockedRedirect, host, ip)
			}
		}
		return nil
	}
}
