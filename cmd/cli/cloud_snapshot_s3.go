package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type s3ObjectState struct {
	ETag         string
	LastModified time.Time
	Size         *int64
}

func (s s3ObjectState) valid() bool {
	return len(s.ETag) > 2 && strings.HasPrefix(s.ETag, "\"") && strings.HasSuffix(s.ETag, "\"") &&
		!s.LastModified.IsZero() && s.Size != nil && *s.Size >= 0
}

func (s s3ObjectState) matches(other s3ObjectState) bool {
	return s.valid() && s.ETag == other.ETag && s.LastModified.Equal(other.LastModified) &&
		other.Size != nil && *s.Size == *other.Size
}

type s3ObjectRead struct {
	ETag          string
	LastModified  time.Time
	ContentLength *int64
	VersionID     string `json:"VersionId"`
	DeleteMarker  bool
	ContentRange  string
}

func (r s3ObjectRead) matches(s s3ObjectState) bool {
	return !r.DeleteMarker && r.ContentRange == "" && s.matches(s3ObjectState{r.ETag, r.LastModified, r.ContentLength})
}

func s3SnapshotArtifacts(ctx context.Context, bucket, prefix string, run snapshotCommand) ([]map[string]string, error) {
	if bucket == "" || !utf8.ValidString(prefix) {
		return nil, errors.New("a valid --bucket and S3 prefix are required")
	}
	listed, err := listS3SnapshotObjects(ctx, bucket, prefix, run)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(listed))
	for key := range listed {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	type manifestEntry struct {
		Key    string `json:"key"`
		SHA256 string `json:"sha256"`
	}
	manifest := make([]manifestEntry, 0, len(keys))
	versions := make(map[string]string, len(keys))
	for _, key := range keys {
		head, err := headS3SnapshotObject(ctx, bucket, key, listed[key], run)
		if err != nil {
			return nil, err
		}
		digest, err := hashS3SnapshotObject(ctx, bucket, key, head, run)
		if err != nil {
			return nil, err
		}
		versions[key] = head.VersionID
		manifest = append(manifest, manifestEntry{key, digest})
	}

	// Listings do not include version IDs, so recheck both membership and current object identity.
	current, err := listS3SnapshotObjects(ctx, bucket, prefix, run)
	if err != nil {
		return nil, err
	}
	if len(current) != len(listed) {
		return nil, errors.New("S3 prefix changed during collection")
	}
	for _, key := range keys {
		if !listed[key].matches(current[key]) {
			return nil, errors.New("S3 prefix changed during collection")
		}
		head, err := headS3SnapshotObject(ctx, bucket, key, current[key], run)
		if err != nil {
			return nil, err
		}
		if head.VersionID != versions[key] {
			return nil, errors.New("S3 object version changed during collection")
		}
	}

	canonical, err := json.Marshal(manifest)
	if err != nil {
		return nil, errors.New("could not encode S3 snapshot manifest")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope := "s3://" + bucket + (&url.URL{Path: "/" + prefix}).EscapedPath()
	if len(scope) > 255 {
		scope = fmt.Sprintf("s3:%x", sha256.Sum256([]byte(scope)))
	}
	return []map[string]string{{"sha256": fmt.Sprintf("%x", sha256.Sum256(canonical)), "service_name": scope}}, nil
}

func listS3SnapshotObjects(ctx context.Context, bucket, prefix string, run snapshotCommand) (map[string]s3ObjectState, error) {
	objects := make(map[string]s3ObjectState)
	tokens := make(map[string]bool)
	input := map[string]string{"Bucket": bucket, "Prefix": prefix, "EncodingType": "url"}
	for {
		var page struct {
			Contents []struct {
				Key string
				s3ObjectState
			}
			EncodingType          string
			IsTruncated           *bool
			KeyCount              *int
			NextContinuationToken string
		}
		if err := runS3SnapshotCommand(ctx, run, "list-objects-v2", input, &page); err != nil {
			return nil, err
		}
		if page.EncodingType != "url" || page.IsTruncated == nil || page.KeyCount == nil || *page.KeyCount != len(page.Contents) ||
			*page.IsTruncated != (page.NextContinuationToken != "") {
			return nil, errors.New("incomplete S3 listing page")
		}
		for _, entry := range page.Contents {
			key, err := url.QueryUnescape(entry.Key)
			if err != nil || key == "" || !utf8.ValidString(key) || !strings.HasPrefix(key, prefix) || !entry.valid() {
				return nil, errors.New("invalid S3 listing entry")
			}
			if _, exists := objects[key]; exists {
				return nil, errors.New("duplicate object in S3 listing")
			}
			objects[key] = entry.s3ObjectState
		}
		if !*page.IsTruncated {
			return objects, nil
		}
		if tokens[page.NextContinuationToken] {
			return nil, errors.New("repeated S3 continuation token")
		}
		tokens[page.NextContinuationToken] = true
		input["ContinuationToken"] = page.NextContinuationToken
	}
}

func headS3SnapshotObject(ctx context.Context, bucket, key string, listed s3ObjectState, run snapshotCommand) (s3ObjectRead, error) {
	var head s3ObjectRead
	err := runS3SnapshotCommand(ctx, run, "head-object", map[string]string{"Bucket": bucket, "Key": key}, &head)
	if err == nil && !head.matches(listed) {
		err = errors.New("S3 object metadata changed during collection")
	}
	return head, err
}

func hashS3SnapshotObject(ctx context.Context, bucket, key string, head s3ObjectRead, run snapshotCommand) (string, error) {
	file, err := os.CreateTemp("", "fides-s3-snapshot-*")
	if err != nil {
		return "", errors.New("could not create private S3 download file")
	}
	defer func() { _ = os.Remove(file.Name()) }()
	defer file.Close()

	input := map[string]string{"Bucket": bucket, "Key": key}
	if head.VersionID != "" && head.VersionID != "null" {
		input["VersionId"] = head.VersionID
	} else {
		input["IfMatch"] = head.ETag
	}
	var got s3ObjectRead
	if err := runS3SnapshotCommand(ctx, run, "get-object", input, &got, file.Name()); err != nil {
		return "", err
	}
	if got.VersionID != head.VersionID || !got.matches(s3ObjectState{head.ETag, head.LastModified, head.ContentLength}) {
		return "", errors.New("S3 download does not match the observed object")
	}

	info, err := file.Stat()
	if err != nil || info.Size() != *head.ContentLength {
		return "", errors.New("incomplete S3 object download")
	}
	hash := sha256.New()
	for remaining := info.Size(); remaining > 0; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := io.CopyN(hash, file, min(remaining, 1024*1024))
		if err != nil {
			return "", errors.New("could not hash S3 download")
		}
		remaining -= n
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), ctx.Err()
}

func runS3SnapshotCommand(ctx context.Context, run snapshotCommand, operation string, input map[string]string, result any, trailing ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Inline JSON keeps provider-controlled keys and tokens literal, including AWS CLI's file:// syntax.
	params, err := json.Marshal(input)
	if err != nil {
		return errors.New("could not encode S3 request")
	}
	args := []string{"s3api", operation, "--no-paginate", "--no-cli-pager", "--no-cli-auto-prompt", "--output", "json", "--cli-input-json", string(params)}
	out, err := run(ctx, "aws", append(args, trailing...)...)
	if err != nil {
		return fmt.Errorf("S3 %s failed", operation)
	}
	if json.Unmarshal(out, result) != nil {
		return fmt.Errorf("invalid S3 %s response", operation)
	}
	return nil
}
