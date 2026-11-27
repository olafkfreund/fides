package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const snapshotTestTimeout = 5 * time.Second

func TestS3Snapshot(t *testing.T) {
	const modified = "2026-11-27T12:00:00+00:00"
	for _, scenario := range []string{"complete", "reordered", "listing changed", "missing token", "repeated token",
		"version changed", "get failed", "short download", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			pages, downloads := 0, 0
			var paths []string
			ctx, cancel := context.WithTimeout(t.Context(), snapshotTestTimeout)
			defer cancel()
			run := func(_ context.Context, name string, args ...string) ([]byte, error) {
				index := slices.Index(args, "--cli-input-json")
				if name != "aws" || args[0] != "s3api" || index < 0 || !slices.Contains(args, "--no-paginate") {
					t.Fatalf("unexpected AWS command %s %v", name, args)
				}
				var input map[string]string
				if err := json.Unmarshal([]byte(args[index+1]), &input); err != nil || input["Bucket"] != "fixture-bucket" {
					t.Fatalf("unexpected AWS input %v, %v", input, err)
				}
				switch args[1] {
				case "list-objects-v2":
					pages++
					second := pages%2 == 0
					if scenario == "missing token" {
						return []byte(`{"EncodingType":"url","IsTruncated":true,"KeyCount":0}`), nil
					}
					if input["Prefix"] != "site/" || input["EncodingType"] != "url" ||
						(second && input["ContinuationToken"] != "opaque%+token") || (!second && input["ContinuationToken"] != "") {
						t.Fatalf("unexpected list input %v", input)
					}
					token := `,"NextContinuationToken":"opaque%+token"`
					if second && scenario != "repeated token" {
						token = ""
					}
					key, etag, size := "site%2Fb", "etag-b", 4
					if second != (scenario == "reordered") {
						key, etag, size = "site%2Fa+with%25%2B", "etag-a", 5
					}
					if scenario == "listing changed" && pages == 4 {
						etag = "changed"
					}
					return fmt.Appendf(nil, `{"EncodingType":"url","IsTruncated":%t,"KeyCount":1%s,
						"Contents":[{"Key":%q,"ETag":%q,"LastModified":%q,"Size":%d}]}`,
						token != "", token, key, `"`+etag+`"`, modified, size), nil

				case "head-object", "get-object":
					body, etag, version := "beta", `"etag-b"`, "null"
					if input["Key"] == "site/a with%+" {
						body, etag, version = "alpha", `"etag-a"`, "immutable-version"
					} else if input["Key"] != "site/b" {
						t.Fatalf("unexpected object key %q", input["Key"])
					}
					if args[1] == "get-object" {
						downloads++
						if (version == "null" && (input["IfMatch"] != etag || input["VersionId"] != "")) ||
							(version != "null" && (input["VersionId"] != version || input["IfMatch"] != "")) {
							t.Fatalf("unexpected object selector %v", input)
						}
						path := args[len(args)-1]
						paths = append(paths, path)
						info, err := os.Stat(path)
						if err != nil || info.Mode().Perm() != 0600 {
							t.Fatalf("download file is not private: %v, %v", info, err)
						}
						if scenario == "get failed" {
							return nil, errors.New("fixture: S3 precondition failed")
						}
						content := body
						if scenario == "short download" {
							content = "x"
						}
						if err := os.WriteFile(path, []byte(content), 0600); err != nil {
							t.Fatal(err)
						}
						if scenario == "canceled" {
							cancel()
						}
					} else if scenario == "version changed" && pages == 4 && version != "null" {
						version = "new-version"
					}
					return fmt.Appendf(nil, `{"ETag":%q,"LastModified":%q,"ContentLength":%d,"VersionId":%q}`,
						etag, modified, len(body), version), nil
				default:
					t.Fatalf("unexpected AWS operation %v", args)
					return nil, nil
				}
			}

			artifacts, err := s3SnapshotArtifacts(ctx, "fixture-bucket", "site/", run)
			for _, path := range paths {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("download file was retained: %v", err)
				}
			}
			if scenario != "complete" && scenario != "reordered" {
				if err == nil || artifacts != nil {
					t.Fatalf("partial observation returned %v, %v", artifacts, err)
				}
				return
			}
			manifest := fmt.Sprintf(`[{"key":"site/a with%%+","sha256":"%x"},{"key":"site/b","sha256":"%x"}]`,
				sha256.Sum256([]byte("alpha")), sha256.Sum256([]byte("beta")))
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(manifest)))
			if err != nil || pages != 4 || downloads != 2 || len(artifacts) != 1 ||
				artifacts[0]["sha256"] != digest || artifacts[0]["service_name"] != "s3://fixture-bucket/site/" {
				t.Fatalf("S3 snapshot = %v, %v, %d pages, %d downloads", artifacts, err, pages, downloads)
			}
		})
	}
}

func TestS3SnapshotEmptyLongPrefix(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), snapshotTestTimeout)
	defer cancel()
	prefix := strings.Repeat("x", 300)
	artifacts, err := s3SnapshotArtifacts(ctx, "fixture-bucket", prefix, func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "aws" || args[1] != "list-objects-v2" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return []byte(`{"EncodingType":"url","IsTruncated":false,"KeyCount":0}`), nil
	})
	wantScope := fmt.Sprintf("s3:%x", sha256.Sum256([]byte("s3://fixture-bucket/"+prefix)))
	wantDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("[]")))
	if err != nil || len(artifacts) != 1 || artifacts[0]["sha256"] != wantDigest || artifacts[0]["service_name"] != wantScope {
		t.Fatalf("unexpected snapshot: %v, %v", artifacts, err)
	}
}
