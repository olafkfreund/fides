package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const azurePackagePath = "/api/vfs/data/SitePackages/"
const azurePackageMaxBytes = 1 << 30

var azureAppName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,58}[a-z0-9]$`)
var azureSiteHost = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*\.azurewebsites\.net$`)
var azureBlobHost = regexp.MustCompile(`^[a-z0-9]{3,24}\.blob\.core\.windows\.net$`)
var azurePackageName = regexp.MustCompile(`^[a-zA-Z0-9_-][a-zA-Z0-9._-]{0,250}\.zip$`)

type azureSnapshotApp struct {
	Name         string
	Kind         string
	State        string
	Availability string
	Host         string
	Modified     string
}

func azureSnapshotArtifacts(ctx context.Context, resourceGroup, app string, run snapshotCommand) ([]map[string]string, error) {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return collectAzureSnapshot(ctx, client, resourceGroup, app, run)
}

func collectAzureSnapshot(ctx context.Context, client *http.Client, resourceGroup, app string, run snapshotCommand) ([]map[string]string, error) {
	app = strings.ToLower(app)
	if !azureAppName.MatchString(app) || strings.TrimSpace(resourceGroup) == "" {
		return nil, errors.New("set --resource-group and a valid --app for the Azure snapshot")
	}
	target := []string{"--resource-group=" + resourceGroup, "--name=" + app}
	observe := func(command []string, query string, value any) error {
		args := append(command, target...)
		args = append(args, "--query", query, "--output", "json", "--only-show-errors")
		out, err := run(ctx, "az", args...)
		if err != nil {
			return errors.New("could not read the app configuration with Azure CLI")
		}
		if json.Unmarshal(out, value) != nil {
			return errors.New("invalid app configuration from Azure CLI")
		}
		return nil
	}
	appInfo := func() (azureSnapshotApp, error) {
		var info azureSnapshotApp
		err := observe([]string{"resource", "show", "--resource-type", "Microsoft.Web/sites"},
			"{name:name,kind:kind,state:properties.state,availability:properties.availabilityState,host:properties.defaultHostName,modified:properties.lastModifiedTimeUtc}", &info)
		if err == nil && (info.Name != app || info.State != "Running" || info.Availability != "Normal" || !azureSiteHost.MatchString(info.Host)) {
			err = errors.New("expected a running and available app at an Azure public-cloud hostname")
		}
		return info, err
	}
	info, err := appInfo()
	if err != nil {
		return nil, err
	}
	command := "webapp"
	if strings.Contains(info.Kind, "functionapp") {
		command = "functionapp"
	}
	readRuntime := func() (string, error) {
		var image string
		err := observe([]string{command, "config", "show"}, "linuxFxVersion", &image)
		return image, err
	}
	runtime, err := readRuntime()
	if err != nil {
		return nil, err
	}
	var digest string
	if image, ok := strings.CutPrefix(runtime, "DOCKER|"); ok {
		name, sha, pinned := strings.Cut(image, "@sha256:")
		if !pinned || name == "" || strings.ContainsAny(name, "@ \t\r\n") || !isSHA256Hex(sha) {
			return nil, errors.New("pin the Azure container image by SHA-256 digest")
		}
		digest = strings.ToLower(sha)
	} else {
		if strings.Contains(info.Kind, "container") || strings.HasPrefix(runtime, "COMPOSE|") || strings.EqualFold(runtime, "sitecontainers") {
			return nil, errors.New("no verifiable single image digest for the Azure container layout")
		}
		readPackage := func() (string, error) {
			var setting string
			err := observe([]string{command, "config", "appsettings", "list"},
				"[?name=='WEBSITE_RUN_FROM_PACKAGE'].value | [0]", &setting)
			return setting, err
		}
		setting, err := readPackage()
		if err != nil {
			return nil, err
		}
		if setting == "1" {
			digest, err = azureLocalPackageDigest(ctx, client, info.Host, run)
		} else {
			digest, err = azureRemotePackageDigest(ctx, client, setting)
		}
		if err != nil {
			return nil, err
		}
		if current, err := readPackage(); err != nil || current != setting {
			return nil, errors.New("could not confirm the active Azure package stayed unchanged")
		}
	}
	if current, err := readRuntime(); err != nil || current != runtime {
		return nil, errors.New("could not confirm Azure runtime configuration stayed unchanged")
	}
	if current, err := appInfo(); err != nil || current != info {
		return nil, errors.New("could not confirm Azure app state stayed unchanged")
	}
	return []map[string]string{{"sha256": digest, "service_name": app}}, nil
}

func azureLocalPackageDigest(ctx context.Context, client *http.Client, host string, run snapshotCommand) (string, error) {
	out, err := run(ctx, "az", "account", "get-access-token", "--resource", "https://management.azure.com/",
		"--query", "accessToken", "--output", "tsv", "--only-show-errors")
	token := strings.TrimSpace(string(out))
	if err != nil || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("could not obtain an Azure token for the app's Kudu endpoint")
	}
	label, suffix, _ := strings.Cut(host, ".")
	base := "https://" + label + ".scm." + suffix + azurePackagePath
	activePackage := func() (string, error) {
		resp, err := azurePackageGET(ctx, client, base+"packagename.txt", token, "")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		file, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		name := strings.TrimSpace(string(file))
		if resp.StatusCode != http.StatusOK || err != nil || len(file) == 1024 || !azurePackageName.MatchString(name) {
			return "", errors.New("could not read a valid active Azure ZIP package name")
		}
		return name, nil
	}
	name, err := activePackage()
	if err != nil {
		return "", err
	}
	digest, etag, err := azurePackageDigest(ctx, client, base+name, token)
	if err != nil {
		return "", err
	}
	if etag == "" || strings.HasPrefix(etag, "W/") {
		return "", errors.New("missing identity for the active Azure ZIP package")
	}
	resp, err := azurePackageGET(ctx, client, base+name, token, etag)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		return "", errors.New("could not confirm the Azure ZIP package stayed unchanged")
	}
	if current, err := activePackage(); err != nil || current != name {
		return "", errors.New("could not confirm the active Azure ZIP package name stayed unchanged")
	}
	return digest, nil
}

func azureRemotePackageDigest(ctx context.Context, client *http.Client, setting string) (string, error) {
	link, err := url.Parse(setting)
	if err != nil || link.Scheme != "https" || link.User != nil || link.Port() != "" || link.Fragment != "" ||
		!azureBlobHost.MatchString(link.Hostname()) {
		return "", errors.New("expected an active Kudu ZIP or a versioned Azure Blob HTTPS URL")
	}
	q, err := url.ParseQuery(link.RawQuery)
	if err != nil || len(q["versionid"]) != 1 || q.Get("versionid") == "" ||
		!strings.HasSuffix(strings.ToLower(link.Path), ".zip") {
		return "", errors.New("the Azure Blob package must specify a single immutable ZIP version")
	}
	digest, _, err := azurePackageDigest(ctx, client, link.String(), "")
	return digest, err
}

func azurePackageGET(ctx context.Context, client *http.Client, target, token, etag string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("invalid Azure package URL")
	}
	req.Header.Set("Accept-Encoding", "identity")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("could not read the Azure package")
	}
	return resp, nil
}

func azurePackageDigest(ctx context.Context, client *http.Client, target, token string) (string, string, error) {
	resp, err := azurePackageGET(ctx, client, target, token, "")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > azurePackageMaxBytes {
		return "", "", fmt.Errorf("could not read the Azure package within the size limit (HTTP %d)", resp.StatusCode)
	}
	body := bufio.NewReader(resp.Body)
	header, err := body.Peek(4)
	if err != nil || string(header) != "PK\x03\x04" {
		return "", "", errors.New("expected a non-empty Azure ZIP package")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(body, azurePackageMaxBytes+1))
	if err != nil || n > azurePackageMaxBytes || (resp.ContentLength >= 0 && n != resp.ContentLength) {
		return "", "", errors.New("could not read the complete Azure ZIP package within the size limit")
	}
	return hex.EncodeToString(hash.Sum(nil)), resp.Header.Get("ETag"), nil
}
