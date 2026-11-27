package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type s3SnapshotClient interface {
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

func newS3SnapshotClient(ctx context.Context) (*s3.Client, error) {
	client := awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
		t.DisableCompression = true // Hash the stored bytes, including gzip-encoded objects.
	})
	cfg, err := config.LoadDefaultConfig(ctx, config.WithHTTPClient(client))
	if err != nil {
		return nil, errors.New("could not load AWS configuration")
	}
	return s3.NewFromConfig(cfg), nil
}

type s3ObjectState struct {
	ETag         *string
	LastModified *time.Time
	Size         *int64
}

func (s s3ObjectState) valid() bool {
	etag := aws.ToString(s.ETag)
	return len(etag) > 2 && strings.HasPrefix(etag, "\"") && strings.HasSuffix(etag, "\"") &&
		s.LastModified != nil && !s.LastModified.IsZero() && s.Size != nil && *s.Size >= 0
}

func (s s3ObjectState) matches(other s3ObjectState) bool {
	return s.valid() && aws.ToString(s.ETag) == aws.ToString(other.ETag) && other.LastModified != nil &&
		s.LastModified.Equal(*other.LastModified) && other.Size != nil && *s.Size == *other.Size
}

func s3SnapshotArtifacts(ctx context.Context, bucket, prefix string, client s3SnapshotClient) ([]map[string]string, error) {
	if bucket == "" || !utf8.ValidString(prefix) {
		return nil, errors.New("a valid --bucket and S3 prefix are required")
	}
	listed, err := listS3SnapshotObjects(ctx, client, bucket, prefix)
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
		head, err := headS3SnapshotObject(ctx, client, bucket, key, listed[key])
		if err != nil {
			return nil, err
		}
		digest, err := hashS3SnapshotObject(ctx, client, bucket, key, head)
		if err != nil {
			return nil, err
		}
		versions[key] = aws.ToString(head.VersionId)
		manifest = append(manifest, manifestEntry{key, digest})
	}

	// Listings do not include version IDs, so recheck both membership and current object identity.
	current, err := listS3SnapshotObjects(ctx, client, bucket, prefix)
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
		head, err := headS3SnapshotObject(ctx, client, bucket, key, current[key])
		if err != nil {
			return nil, err
		}
		if aws.ToString(head.VersionId) != versions[key] {
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

func listS3SnapshotObjects(ctx context.Context, client s3SnapshotClient, bucket, prefix string) (map[string]s3ObjectState, error) {
	objects := make(map[string]s3ObjectState)
	tokens := make(map[string]bool)
	input := &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix), EncodingType: types.EncodingTypeUrl}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, errors.New("could not list S3 prefix")
		}
		if page == nil {
			return nil, errors.New("missing S3 listing page")
		}
		token := aws.ToString(page.NextContinuationToken)
		if page.EncodingType != types.EncodingTypeUrl || page.IsTruncated == nil || page.KeyCount == nil || int(*page.KeyCount) != len(page.Contents) ||
			*page.IsTruncated != (token != "") {
			return nil, errors.New("incomplete S3 listing page")
		}
		for _, entry := range page.Contents {
			key, err := url.QueryUnescape(aws.ToString(entry.Key))
			state := s3ObjectState{entry.ETag, entry.LastModified, entry.Size}
			if err != nil || key == "" || !utf8.ValidString(key) || !strings.HasPrefix(key, prefix) || !state.valid() {
				return nil, errors.New("invalid S3 listing entry")
			}
			if _, exists := objects[key]; exists {
				return nil, errors.New("duplicate object in S3 listing")
			}
			objects[key] = state
		}
		if !*page.IsTruncated {
			return objects, nil
		}
		if tokens[token] {
			return nil, errors.New("repeated S3 continuation token")
		}
		tokens[token] = true
		input.ContinuationToken = page.NextContinuationToken
	}
}

func headS3SnapshotObject(ctx context.Context, client s3SnapshotClient, bucket, key string, listed s3ObjectState) (*s3.HeadObjectOutput, error) {
	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, errors.New("could not read S3 object metadata")
	}
	if head == nil || aws.ToBool(head.DeleteMarker) || aws.ToString(head.ContentRange) != "" ||
		!listed.matches(s3ObjectState{head.ETag, head.LastModified, head.ContentLength}) {
		return nil, errors.New("S3 object metadata changed during collection")
	}
	return head, nil
}

func hashS3SnapshotObject(ctx context.Context, client s3SnapshotClient, bucket, key string, head *s3.HeadObjectOutput) (string, error) {
	input := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
	if v := aws.ToString(head.VersionId); v != "" && v != "null" {
		input.VersionId = head.VersionId
	} else {
		input.IfMatch = head.ETag
	}
	got, err := client.GetObject(ctx, input)
	if err != nil {
		return "", errors.New("could not read S3 object")
	}
	if got == nil || got.Body == nil {
		return "", errors.New("missing S3 object body")
	}
	defer got.Body.Close()
	state := s3ObjectState{head.ETag, head.LastModified, head.ContentLength}
	if aws.ToBool(got.DeleteMarker) || aws.ToString(got.ContentRange) != "" ||
		aws.ToString(got.VersionId) != aws.ToString(head.VersionId) ||
		!state.matches(s3ObjectState{got.ETag, got.LastModified, got.ContentLength}) {
		return "", errors.New("S3 download does not match the observed object")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, got.Body)
	if err != nil || n != *head.ContentLength {
		return "", errors.New("incomplete S3 object download")
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), ctx.Err()
}
