package parser

import (
	"fmt"
	"net/url"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseSSH handles the project's ssh:// share link.
//
//	ssh://user:pass@host:port?private-key=...&private-key-passphrase=...
//	    &host-key=...&host-key-algorithms=...#name
func parseSSH(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	if host == "" || port == 0 {
		return nil, fmt.Errorf("ssh: missing host/port")
	}
	username := u.User.Username()
	if username == "" {
		return nil, fmt.Errorf("ssh: missing username")
	}
	pass, _ := u.User.Password()
	q := lowerQuery(u.Query())
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("ssh", name, host, port)
	p.Set("username", username)
	p.Set("password", pass)
	p.Set("private-key", firstQ(q, "private-key", "privatekey", "private_key"))
	p.Set("private-key-passphrase",
		firstQ(q, "private-key-passphrase", "privatekeypassphrase", "private_key_passphrase", "passphrase"))
	if hostKey := firstQ(q, "host-key", "hostkey", "host_key"); hostKey != "" {
		p.Set("host-key", splitALPN(hostKey))
	}
	if algs := firstQ(q, "host-key-algorithms", "hostkeyalgorithms", "host_key_algorithms"); algs != "" {
		p.Set("host-key-algorithms", splitALPN(algs))
	}
	return p, nil
}
