package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"time"

	"fides/internal/pagination"
)

// httpClient is shared across CLI requests and enforces an overall timeout so a
// hung server cannot block the CLI indefinitely.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// getRequest performs an authenticated GET and returns the response body.
func getRequest(config CLIConfig, path string) (string, error) {
	body, _, err := getPage(httpClient, config.Token, config.ServerURL+path)
	return string(body), err
}

func getList(config CLIConfig, path string) (string, error) {
	return getListUpTo(config, path, 0)
}

func getListUpTo(config CLIConfig, path string, limit int) (string, error) {
	body, err := pagination.ReadList(httpClient, config.ServerURL+path, limit, func(client *http.Client, url string) ([]byte, *http.Response, error) {
		return getPage(client, config.Token, url)
	})
	return string(body), err
}

func getPage(client *http.Client, token, url string) ([]byte, *http.Response, error) {
	req, err := http.NewRequest("GET", url, nil) // #nosec G704 -- configured server or a validated same-origin page URL
	if err != nil {
		return nil, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req) // #nosec G704 -- configured server or a validated same-origin page URL
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("server returned error code: %d, body: %s", resp.StatusCode, string(b))
	}
	return b, resp, nil
}

func postRequest(config CLIConfig, path string, data interface{}) (string, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", config.ServerURL+path, bytes.NewBuffer(body)) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := httpClient.Do(req) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("server returned error code: %d, body: %s", resp.StatusCode, string(respBytes))
	}

	return string(respBytes), nil
}

// deleteRequest performs an authenticated DELETE.
func deleteRequest(config CLIConfig, path string) (string, error) {
	req, err := http.NewRequest("DELETE", config.ServerURL+path, nil) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	resp, err := httpClient.Do(req) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("server returned error code: %d, body: %s", resp.StatusCode, string(b))
	}
	return string(b), nil
}

// post is a small helper: POST json, print success message (or the body), exit on error.
func post(config CLIConfig, path string, payload any, successMsg string) {
	body, err := postRequest(config, path, payload)
	fail(err, "request to "+path)
	if successMsg != "" {
		fmt.Println(successMsg)
	} else {
		fmt.Println(body)
	}
}

func fail(err error, what string) {
	if err != nil {
		fmt.Printf("Failed: %s: %v\n", what, err)
		os.Exit(1)
	}
}

func setIf(q neturl.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}
