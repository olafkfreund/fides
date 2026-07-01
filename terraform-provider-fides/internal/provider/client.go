package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a thin REST client for the Fides API used by the provider.
type Client struct {
	Endpoint string
	Token    string
	http     *http.Client
}

func NewClient(endpoint, token string) *Client {
	return &Client{Endpoint: endpoint, Token: token, http: &http.Client{Timeout: 30 * time.Second}}
}

// do performs a request and returns the body and status. body may be nil.
func (c *Client) do(method, path string, body any) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.Endpoint+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return out, resp.StatusCode, fmt.Errorf("fides API %s %s -> %d: %s", method, path, resp.StatusCode, string(out))
	}
	return out, resp.StatusCode, nil
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
	_, _, err := c.do("POST", "/api/v1/controls", map[string]any{
		"key": ct.Key, "name": ct.Name, "description": ct.Description,
		"framework": ct.Framework, "required_types": ct.RequiredTypes,
	})
	return err
}

// GetControlByKey returns the control with the given key, or nil if absent.
func (c *Client) GetControlByKey(key string) (*Control, error) {
	out, _, err := c.do("GET", "/api/v1/controls?include_archived=true", nil)
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
	return nil, nil
}

// ArchiveControl archives (soft-deletes) a control by id.
func (c *Client) ArchiveControl(id string) error {
	_, _, err := c.do("POST", "/api/v1/controls/"+id+"/archive", map[string]any{})
	return err
}
