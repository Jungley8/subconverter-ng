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

var (
	cgnatPrefix       = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)
	thisHostPrefix    = netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 8)
	reservedPrefix    = netip.PrefixFrom(netip.AddrFrom4([4]byte{240, 0, 0, 0}), 4)
	ietfPrefix        = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 0, 0}), 24)
	testnet1Prefix    = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 24)
	benchPrefix       = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 0, 0}), 15)
	testnet2Prefix    = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, 0}), 24)
	testnet3Prefix    = netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, 0}), 24)
	ipv6DocPrefix     = netip.MustParsePrefix("2001:db8::/32")
	ipv6DiscardPrefix = netip.MustParsePrefix("100::/64")
)

// isBlockedIP reports whether ip is a private, loopback, link-local, multicast,
// unspecified, carrier-grade NAT, or reserved/special address.
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
	// Broadcast
	if addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	// 0.0.0.0/8 (This host on this network, RFC 1122)
	if thisHostPrefix.Contains(addr) {
		return true
	}
	// Carrier-Grade NAT (CGNAT) RFC 6598: 100.64.0.0/10
	if cgnatPrefix.Contains(addr) {
		return true
	}
	// Reserved / Benchmark / Test ranges
	if reservedPrefix.Contains(addr) ||
		ietfPrefix.Contains(addr) ||
		testnet1Prefix.Contains(addr) ||
		benchPrefix.Contains(addr) ||
		testnet2Prefix.Contains(addr) ||
		testnet3Prefix.Contains(addr) {
		return true
	}
	// IPv6 Special Ranges
	if ipv6DocPrefix.Contains(addr) || ipv6DiscardPrefix.Contains(addr) {
		return true
	}
	return false
}

// isBlockedHostname checks whether a hostname is a loopback or internal name.
func isBlockedHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "localhost" ||
		strings.HasSuffix(h, ".localhost") ||
		strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".lan") ||
		strings.HasSuffix(h, ".home.arpa") {
		return true
	}
	return false
}

// ValidateTargetURL validates an HTTP/HTTPS target URL against SSRF before dialing.
func ValidateTargetURL(raw string, allowPrivate bool) error {
	return validateURLWithSchemes(raw, allowPrivate, []string{"http", "https"})
}

// ValidateProxyURL validates an upstream proxy URL against SSRF before use.
func ValidateProxyURL(raw string, allowPrivate bool) error {
	return validateURLWithSchemes(raw, allowPrivate, []string{"http", "https", "socks5", "socks5h"})
}

func validateTargetURL(raw string, allowPrivate bool) error {
	return ValidateTargetURL(raw, allowPrivate)
}

func validateURLWithSchemes(raw string, allowPrivate bool, allowedSchemes []string) error {
	if allowPrivate {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	allowed := false
	for _, s := range allowedSchemes {
		if scheme == s {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unsupported scheme %q (allowed: %s)", scheme, strings.Join(allowedSchemes, ", "))
	}
	hostname := u.Hostname()
	if hostname == "" {
		return errors.New("missing host in URL")
	}
	if isBlockedHostname(hostname) {
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
func safeDialContext(dialer *net.Dialer, allowPrivate bool, trustedProxyHost string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// When allowPrivate is true or dialing the operator's explicitly configured trusted proxy host, allow direct dial.
		if allowPrivate || (trustedProxyHost != "" && strings.EqualFold(host, trustedProxyHost)) {
			return dialer.DialContext(ctx, network, addr)
		}

		if isBlockedHostname(host) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedIP, host)
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

		// Connect directly to the validated IP addresses in order to prevent DNS rebinding TOCTOU
		var lastErr error
		for _, ip := range ips {
			targetAddr := net.JoinHostPort(ip.String(), port)
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
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
		if isBlockedHostname(host) {
			return fmt.Errorf("%w: %s", ErrBlockedRedirect, host)
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
