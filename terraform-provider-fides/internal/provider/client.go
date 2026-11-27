package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a thin REST client for the Fides API used by the provider.
type Client struct {
	Endpoint string
	Token    string
	http     *http.Client
}

type apiError struct {
	method, path string
	status       int
	body         string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("fides API %s %s -> %d: %s", e.method, e.path, e.status, e.body)
}

func NewClient(endpoint, token string) *Client {
	return &Client{Endpoint: endpoint, Token: token, http: &http.Client{Timeout: 30 * time.Second}}
}

// do performs a request and returns the body and response headers.
func (c *Client) do(method, endpoint string, body any) ([]byte, http.Header, error) {
	return c.doContext(context.Background(), method, endpoint, body)
}

func (c *Client) doContext(ctx context.Context, method, endpoint string, body any) ([]byte, http.Header, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, &apiError{method: method, path: req.URL.Path, status: resp.StatusCode, body: string(out)}
	}
	return out, resp.Header, nil
}

// Control mirrors the Fides controls API shape.
type Control struct {
	ID            string   `json:"id"`
	Key           string   `json:"key"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Framework     string   `json:"framework"`
	RequiredTypes []string `json:"required_types"`
	Archived      bool     `json:"archived"`
}

// UpsertControl creates/updates a control (POST /api/v1/controls upserts by key).
func (c *Client) UpsertControl(ct Control) error {
	_, _, err := c.do("POST", c.Endpoint+"/api/v1/controls", map[string]any{
		"key": ct.Key, "name": ct.Name, "description": ct.Description,
		"framework": ct.Framework, "required_types": ct.RequiredTypes,
	})
	return err
}

// GetControlByKey returns the control with the given key, or nil if absent.
func (c *Client) GetControlByKey(key string) (*Control, error) {
	current, err := url.Parse(c.Endpoint + "/api/v1/controls?include_archived=true")
	if err != nil {
		return nil, err
	}
	queried := map[string]bool{}
	for {
		endpoint := current.String()
		if queried[endpoint] {
			return nil, fmt.Errorf("fides API repeated a control pagination link")
		}
		queried[endpoint] = true
		out, headers, err := c.do(http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		var list []Control
		if err := json.Unmarshal(out, &list); err != nil {
			return nil, err
		}
		for i := range list {
			if list[i].Key == key {
				return &list[i], nil
			}
		}
		target, next := strings.CutSuffix(headers.Get("Link"), `>; rel="next"`)
		if !next || !strings.HasPrefix(target, "<") {
			return nil, nil
		}
		nextURL, err := current.Parse(strings.TrimPrefix(target, "<"))
		if err != nil || nextURL.User != nil || nextURL.Scheme != current.Scheme || !strings.EqualFold(nextURL.Host, current.Host) {
			return nil, fmt.Errorf("fides API returned an invalid control pagination link")
		}
		current = nextURL
	}
}

// ArchiveControl archives (soft-deletes) a control by id.
func (c *Client) ArchiveControl(id string) error {
	_, _, err := c.do("POST", c.Endpoint+"/api/v1/controls/"+id+"/archive", map[string]any{})
	return err
}
