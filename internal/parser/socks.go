package parser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseSOCKS handles socks://, socks5://, socks5h://, socks4://, socks4a://, and tg://socks links.
//
//	socks5://[user:pass@]host:port#name
//	socks5://[base64(user:pass)@]host:port#name
//	socks5://base64([user:pass@]host:port)#name
//	tg://socks?server=host&port=port&user=user&pass=pass#name
func parseSOCKS(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("socks: %w", err)
	}

	var host, username, password string
	var port int

	if strings.HasPrefix(strings.ToLower(uri), "tg://") {
		q := u.Query()
		host = q.Get("server")
		port = atoiPort(q.Get("port"))
		username = q.Get("user")
		password = q.Get("pass")
	} else {
		host = u.Hostname()
		port = atoiPort(u.Port())

		// If host/port could not be parsed directly, try base64 decoding the host part.
		if (host == "" || port == 0) && u.Host != "" {
			if dec, ok := b64decode(u.Host); ok && dec != u.Host {
				if at := strings.LastIndex(dec, "@"); at != -1 {
					username, password = splitCred(dec[:at])
					host, port = splitHostPort(dec[at+1:])
				} else {
					host, port = splitHostPort(dec)
				}
			}
		}

		if u.User != nil {
			username = u.User.Username()
			password, _ = u.User.Password()
			// Some producers base64 the whole "user:pass" in the userinfo.
			if password == "" && username != "" {
				if dec, ok := b64decode(username); ok && strings.Contains(dec, ":") {
					username, password = splitCred(dec)
				}
			}
		}
	}

	if host == "" || port == 0 {
		return nil, fmt.Errorf("socks: missing host/port")
	}
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("socks5", name, host, port)
	p.Set("username", username)
	p.Set("password", password)
	p.SetRaw("udp", true)
	return p, nil
}
