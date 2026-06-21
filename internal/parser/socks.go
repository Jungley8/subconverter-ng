package parser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseSOCKS handles socks:// and socks5:// links.
//
//	socks5://[base64(user:pass)@]host:port#name
//	socks5://user:pass@host:port#name
func parseSOCKS(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("socks: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	if host == "" || port == 0 {
		return nil, fmt.Errorf("socks: missing host/port")
	}
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
		// Some producers base64 the whole "user:pass" in the userinfo.
		if password == "" && username != "" {
			if dec, ok := b64decode(username); ok && strings.Contains(dec, ":") {
				idx := strings.Index(dec, ":")
				username = dec[:idx]
				password = dec[idx+1:]
			}
		}
	}

	p := proxy.New("socks5", name, host, port)
	p.Set("username", username)
	p.Set("password", password)
	p.SetRaw("udp", true)
	return p, nil
}
