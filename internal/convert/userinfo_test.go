package convert

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// metaFetcher is a fakeFetcher that also returns headers, exercising the
// MetaFetcher fast path. It returns the userinfo header only for the URL whose
// key it is configured with.
type metaFetcher struct {
	fakeFetcher
	userinfoKey string // body key whose response carries Subscription-Userinfo
	userinfo    string
}

func (m metaFetcher) GetWithMeta(ctx context.Context, url string) ([]byte, http.Header, error) {
	body, err := m.fakeFetcher.Get(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	var hdr http.Header
	if m.userinfoKey != "" && strings.Contains(url, m.userinfoKey) {
		hdr = http.Header{"Subscription-Userinfo": []string{m.userinfo}}
	}
	return body, hdr, nil
}

func TestRun_CapturesSubscriptionUserinfo(t *testing.T) {
	const ui = "upload=100; download=200; total=1000; expire=1700000000"
	f := metaFetcher{
		fakeFetcher: fakeFetcher{
			"client/subscribe": sampleSubscription(),
			"config.init":      []byte(sampleINI),
			"PROXY.list":       []byte(samplePROXYList),
		},
		userinfoKey: "client/subscribe",
		userinfo:    ui,
	}
	req := Request{
		Target:    "clash",
		SubURLs:   []string{"https://airport.example.com/api/v1/client/subscribe?token=x"},
		ConfigURL: "https://github.com/x/config.init",
	}
	_, diag, err := Run(context.Background(), f, req)
	if err != nil {
		t.Fatal(err)
	}
	if diag.SubscriptionUserinfo != ui {
		t.Errorf("SubscriptionUserinfo = %q, want %q", diag.SubscriptionUserinfo, ui)
	}
}

func TestRun_PlainFetcherNoUserinfo(t *testing.T) {
	// A plain Fetcher (no GetWithMeta) must still work; userinfo is empty.
	f := fakeFetcher{
		"client/subscribe": sampleSubscription(),
	}
	req := Request{
		Target:  "clash",
		SubURLs: []string{"https://airport/api/v1/client/subscribe"},
	}
	_, diag, err := Run(context.Background(), f, req)
	if err != nil {
		t.Fatal(err)
	}
	if diag.SubscriptionUserinfo != "" {
		t.Errorf("SubscriptionUserinfo = %q, want empty", diag.SubscriptionUserinfo)
	}
}
