package parser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseSSR handles ssr:// (ShadowsocksR) links.
//
// The body after the scheme is base64 of:
//
//	host:port:protocol:method:obfs:base64pass/?obfsparam=base64&protoparam=base64
//	    &remarks=base64&group=base64
func parseSSR(uri string) (*proxy.Proxy, error) {
	raw := strings.TrimPrefix(uri, "ssr://")
	decoded, ok := b64decode(raw)
	if !ok {
		return nil, fmt.Errorf("ssr: bad base64")
	}

	// Split the params off from the "host:port:...:passEnc" head.
	head := decoded
	var rawQuery string
	if i := strings.Index(decoded, "/?"); i != -1 {
		head = decoded[:i]
		rawQuery = decoded[i+2:]
	} else if i := strings.Index(decoded, "?"); i != -1 {
		head = decoded[:i]
		rawQuery = decoded[i+1:]
	}

	parts := strings.Split(head, ":")
	if len(parts) < 6 {
		return nil, fmt.Errorf("ssr: malformed body")
	}
	host := parts[0]
	port := atoiPort(parts[1])
	protocol := parts[2]
	method := parts[3]
	obfs := parts[4]
	// Password may itself contain ':' theoretically; rejoin the tail.
	passEnc := strings.Join(parts[5:], ":")
	password, _ := b64decode(passEnc)

	if host == "" || port == 0 {
		return nil, fmt.Errorf("ssr: missing host/port")
	}

	q, _ := url.ParseQuery(rawQuery)
	obfsParam, _ := b64decode(q.Get("obfsparam"))
	protoParam, _ := b64decode(q.Get("protoparam"))
	remarks, _ := b64decode(q.Get("remarks"))

	name := strings.TrimSpace(remarks)
	if name == "" {
		name = fmt.Sprintf("%s:%d", host, port)
	}

	p := proxy.New("ssr", name, host, port)
	p.Set("cipher", method)
	p.Set("password", password)
	p.Set("protocol", protocol)
	p.Set("obfs", obfs)
	p.Set("protocol-param", protoParam)
	p.Set("obfs-param", obfsParam)
	p.SetRaw("udp", true)
	return p, nil
}
