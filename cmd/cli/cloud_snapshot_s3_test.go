package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const snapshotTestTimeout = 5 * time.Second

const (
	s3FixtureBucket = "fixture-bucket"
	s3FixturePrefix = "site/"
	s3FixtureKey    = "site/a with%+"
	s3FixtureToken  = "opaque%+token"
)

type s3SnapshotFixture struct {
	t        *testing.T
	scenario string
	modified time.Time
	cancel   context.CancelFunc
	tempDir  string
	pages    int
	streams  []*s3FixtureBody
}

func (f *s3SnapshotFixture) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.t.Helper()
	f.pages++
	second := f.pages%2 == 0
	wantToken := ""
	if second {
		wantToken = s3FixtureToken
	}
	if aws.ToString(in.Bucket) != s3FixtureBucket || aws.ToString(in.Prefix) != s3FixturePrefix ||
		in.EncodingType != types.EncodingTypeUrl || aws.ToString(in.ContinuationToken) != wantToken {
		f.t.Fatalf("unexpected list input %#v", in)
	}
	out := &s3.ListObjectsV2Output{EncodingType: types.EncodingTypeUrl, IsTruncated: aws.Bool(true)}
	if f.scenario == "missing token" {
		out.KeyCount = aws.Int32(0)
		return out, nil
	}
	if !second || f.scenario == "repeated token" {
		out.NextContinuationToken = aws.String(s3FixtureToken)
	} else {
		out.IsTruncated = aws.Bool(false)
	}
	key, etag, size := "site%2Fb", `"etag-b"`, int64(4)
	if second != (f.scenario == "reordered") {
		key, etag, size = "site%2Fa+with%25%2B", `"etag-a"`, 5
	}
	if f.scenario == "listing changed" && f.pages == 4 {
		etag = `"changed"`
	}
	out.KeyCount = aws.Int32(1)
	out.Contents = []types.Object{{
		Key: aws.String(key), ETag: aws.String(etag), Size: aws.Int64(size), LastModified: &f.modified,
	}}
	return out, nil
}

func (f *s3SnapshotFixture) object(bucket, key string) (body, etag, version string) {
	f.t.Helper()
	if bucket != s3FixtureBucket {
		f.t.Fatalf("unexpected object bucket %q", bucket)
	}
	switch key {
	case s3FixtureKey:
		return "alpha", `"etag-a"`, "immutable-version"
	case "site/b":
		return "beta", `"etag-b"`, "null"
	default:
		f.t.Fatalf("unexpected object key %q", key)
		return "", "", ""
	}
}

func (f *s3SnapshotFixture) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	body, etag, version := f.object(aws.ToString(in.Bucket), aws.ToString(in.Key))
	if f.scenario == "version changed" && f.pages == 4 && version != "null" {
		version = "new-version"
	}
	return &s3.HeadObjectOutput{
		ETag: aws.String(etag), LastModified: &f.modified, ContentLength: aws.Int64(int64(len(body))), VersionId: aws.String(version),
	}, nil
}

func (f *s3SnapshotFixture) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	body, etag, version := f.object(aws.ToString(in.Bucket), aws.ToString(in.Key))
	if (version == "null" && (aws.ToString(in.IfMatch) != etag || in.VersionId != nil)) ||
		(version != "null" && (aws.ToString(in.VersionId) != version || in.IfMatch != nil)) {
		f.t.Fatalf("unexpected object selector IfMatch=%q VersionId=%q", aws.ToString(in.IfMatch), aws.ToString(in.VersionId))
	}
	if f.scenario == "get failed" {
		return nil, errors.New("fixture: S3 precondition failed")
	}

	content := body
	if f.scenario == "short download" {
		content = "x"
	}
	stream := &s3FixtureBody{reader: strings.NewReader(content), beforeRead: func() {
		files, err := os.ReadDir(f.tempDir)
		if err != nil || len(files) != 0 {
			f.t.Fatalf("unexpected temporary files during stream read: %v, %v", files, err)
		}
		if f.scenario == "canceled" {
			f.cancel()
		}
	}}
	f.streams = append(f.streams, stream)
	return &s3.GetObjectOutput{
		Body: stream, ETag: aws.String(etag), LastModified: &f.modified, ContentLength: aws.Int64(int64(len(body))), VersionId: aws.String(version),
	}, nil
}

type s3FixtureBody struct {
	reader     *strings.Reader
	beforeRead func()
	closed     bool
}

func (b *s3FixtureBody) Read(p []byte) (int, error) {
	if b.beforeRead != nil {
		b.beforeRead()
		b.beforeRead = nil
	}
	return b.reader.Read(p)
}

func (b *s3FixtureBody) Close() error {
	b.closed = true
	return nil
}

func TestS3Snapshot(t *testing.T) {
	for _, scenario := range []string{"complete", "reordered", "listing changed", "missing token", "repeated token",
		"version changed", "get failed", "short download", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), snapshotTestTimeout)
			defer cancel()
			fixture := &s3SnapshotFixture{
				t: t, scenario: scenario, cancel: cancel, tempDir: t.TempDir(),
				modified: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC),
			}
			t.Setenv("TMPDIR", fixture.tempDir)
			artifacts, err := s3SnapshotArtifacts(ctx, s3FixtureBucket, s3FixturePrefix, fixture)
			for _, stream := range fixture.streams {
				if !stream.closed {
					t.Error("download body was left open")
				}
			}
			switch scenario {
			case "complete", "reordered":
				manifest := fmt.Sprintf(`[{"key":%q,"sha256":"%x"},{"key":"site/b","sha256":"%x"}]`,
					s3FixtureKey, sha256.Sum256([]byte("alpha")), sha256.Sum256([]byte("beta")))
				digest := fmt.Sprintf("%x", sha256.Sum256([]byte(manifest)))
				if err != nil || fixture.pages != 4 || len(fixture.streams) != 2 || len(artifacts) != 1 ||
					artifacts[0]["sha256"] != digest || artifacts[0]["service_name"] != "s3://fixture-bucket/site/" {
					t.Fatalf("S3 snapshot = %v, %v, %d pages, %d downloads", artifacts, err, fixture.pages, len(fixture.streams))
				}
			default:
				if err == nil || artifacts != nil {
					t.Fatalf("partial observation returned %v, %v", artifacts, err)
				}
				if scenario == "canceled" && ctx.Err() != context.Canceled {
					t.Fatal("download never reached the cancellation fixture")
				}
			}
		})
	}
}

func TestS3SnapshotEmptyLongPrefix(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), snapshotTestTimeout)
	defer cancel()
	prefix := strings.Repeat("x", 300)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		query := req.URL.Query()
		if req.Method != http.MethodGet || req.URL.Path != "/"+s3FixtureBucket ||
			query.Get("list-type") != "2" || query.Get("prefix") != prefix || query.Get("encoding-type") != "url" {
			t.Errorf("unexpected SDK request %s %s", req.Method, req.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
			<EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><KeyCount>0</KeyCount>
			</ListBucketResult>`)
	}))
	defer server.Close()
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(server.URL), UsePathStyle: true, Region: "us-east-1",
		HTTPClient: server.Client(), Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{},
	})
	artifacts, err := s3SnapshotArtifacts(ctx, s3FixtureBucket, prefix, client)
	wantScope := fmt.Sprintf("s3:%x", sha256.Sum256([]byte("s3://"+s3FixtureBucket+"/"+prefix)))
	wantDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("[]")))
	if err != nil || len(artifacts) != 1 || artifacts[0]["sha256"] != wantDigest || artifacts[0]["service_name"] != wantScope {
		t.Fatalf("unexpected snapshot: %v, %v", artifacts, err)
	}
}
