package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// FlareSolverr request/response shapes (v1 API).
type fsRequest struct {
	Cmd        string `json:"cmd"`
	URL        string `json:"url"`
	MaxTimeout int    `json:"maxTimeout"`
	Proxy      *fsProxy `json:"proxy,omitempty"`
}

type fsProxy struct {
	URL string `json:"url"`
}

type fsCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type fsResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	Solution struct {
		URL       string     `json:"url"`
		UserAgent string     `json:"userAgent"`
		Cookies   []fsCookie `json:"cookies"`
	} `json:"solution"`
}

// solveCloudflare asks FlareSolverr to render target through a headless browser,
// returning the resulting cookie header and the browser User-Agent. cf_clearance
// is bound to that UA and the egress IP, so the caller must replay using both
// (and through the same upstream proxy, which we forward to FlareSolverr).
func (c *Client) solveCloudflare(ctx context.Context, target string) (cookieHeader, userAgent string, err error) {
	reqBody := fsRequest{
		Cmd:        "request.get",
		URL:        target,
		MaxTimeout: 60000,
	}
	if c.opts.Proxy != "" {
		reqBody.Proxy = &fsProxy{URL: c.opts.Proxy}
	}
	buf, _ := json.Marshal(reqBody)

	// FlareSolverr can take a while to spin up the browser; give it room.
	fsCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(fsCtx, http.MethodPost, c.opts.FlareSolverrURL, bytes.NewReader(buf))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("call flaresolverr: %w", err)
	}
	defer resp.Body.Close()

	var fr fsResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return "", "", fmt.Errorf("decode flaresolverr: %w", err)
	}
	if !strings.EqualFold(fr.Status, "ok") {
		return "", "", fmt.Errorf("flaresolverr status %q: %s", fr.Status, fr.Message)
	}

	var parts []string
	for _, ck := range fr.Solution.Cookies {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; "), fr.Solution.UserAgent, nil
}
