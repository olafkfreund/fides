package pagination

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Fides emits a relative target followed by rel="next".
var nextLink = regexp.MustCompile(`(?i)(?:^|,)\s*<([^>]+)>\s*;\s*rel\s*=\s*(?:"next"|next)(?:\s*[,;]|\s*$)`)

// Next resolves the same-origin continuation in a collection response.
func Next(current *url.URL, headers http.Header) (*url.URL, error) {
	for _, link := range headers.Values("Link") {
		if match := nextLink.FindStringSubmatch(link); match != nil {
			next, err := current.Parse(match[1])
			if err != nil {
				return nil, fmt.Errorf("invalid pagination link: %w", err)
			}
			if !sameOrigin(current, next) {
				return nil, fmt.Errorf("pagination link points outside the Fides server")
			}
			next.Fragment = ""
			return next, nil
		}
	}
	return nil, nil
}

func originPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func sameOrigin(a, b *url.URL) bool {
	return b.User == nil && a.Scheme == b.Scheme &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && originPort(a) == originPort(b)
}

// ReadList reads a paginated array. A positive limit bounds the total returned items.
func ReadList(client *http.Client, start string, limit int, get func(*http.Client, string) ([]byte, *http.Response, error)) ([]byte, error) {
	origin, err := url.Parse(start)
	if err != nil {
		return nil, err
	}
	pageClient := *client
	pageClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !sameOrigin(origin, req.URL) {
			return fmt.Errorf("pagination request redirected outside the Fides server")
		}
		if client.CheckRedirect != nil {
			return client.CheckRedirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}

	seen := map[string]bool{}
	rows := []json.RawMessage{}
	for page := origin; page != nil; {
		key := page.String()
		if seen[key] {
			return nil, fmt.Errorf("repeated pagination link")
		}
		body, response, err := get(&pageClient, key)
		if err != nil {
			return nil, err
		}
		next, err := Next(response.Request.URL, response.Header)
		if err != nil {
			return nil, err
		}
		if len(seen) == 0 && next == nil && limit == 0 {
			return body, nil
		}
		var chunk []json.RawMessage
		if err := json.Unmarshal(body, &chunk); err != nil {
			return nil, fmt.Errorf("decode list page: %w", err)
		}
		rows = append(rows, chunk...)
		if limit > 0 && len(rows) >= limit {
			return json.Marshal(rows[:limit])
		}
		seen[key] = true
		page = next
	}
	return json.Marshal(rows)
}
