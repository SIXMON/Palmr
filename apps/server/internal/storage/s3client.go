// Package storage owns the S3 client and the presigned-URL helpers.
//
// Two clients are kept side by side: an internal one for server-to-S3
// traffic (uses S3_ENDPOINT directly), and a public-facing one for
// presigned URLs handed to the browser (uses STORAGE_URL when set).
// Mirrors apps/server/src/config/storage.config.ts.
package storage

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/sixmon/palmr/apps/server/internal/config"
)

type S3 struct {
	Client    *s3.Client
	Pub       *s3.Client
	Presigner *s3.PresignClient
	PubPresigner *s3.PresignClient
	Bucket    string
	TTL       time.Duration
}

// New returns a wired-up S3 client pair, or nil if S3 isn't configured
// (the file/share modules degrade to disabled features in that case).
func New(ctx context.Context, c *config.Config) (*S3, error) {
	if c.S3Endpoint == "" || c.S3AccessKey == "" || c.S3SecretKey == "" {
		return nil, nil
	}

	internalEndpoint := buildEndpoint(c.S3Endpoint, c.S3Port, c.S3UseSSL)

	httpClient := &http.Client{Timeout: 5 * time.Minute}
	if c.S3UseSSL && !c.S3RejectUnauth {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient.Transport = tr
	}

	cfg, err := awscfg.LoadDefaultConfig(ctx,
		awscfg.WithRegion(c.S3Region),
		awscfg.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.S3AccessKey, c.S3SecretKey, "")),
		awscfg.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	internal := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(internalEndpoint)
		o.UsePathStyle = c.S3ForcePath
	})

	// Public client used for presigned URLs handed to the browser.
	publicEndpoint := internalEndpoint
	if c.StorageURL != "" {
		publicEndpoint = strings.TrimRight(c.StorageURL, "/")
	}
	publicC := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(publicEndpoint)
		o.UsePathStyle = c.S3ForcePath
	})

	return &S3{
		Client:       internal,
		Pub:          publicC,
		Presigner:    s3.NewPresignClient(internal),
		PubPresigner: s3.NewPresignClient(publicC),
		Bucket:       c.S3BucketName,
		TTL:          time.Duration(c.PresignedURLTTL) * time.Second,
	}, nil
}

func buildEndpoint(host string, port int, useSSL bool) string {
	scheme := "http"
	if useSSL {
		scheme = "https"
	}
	// Strip protocol from host if present (defensive).
	host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	if port > 0 {
		return scheme + "://" + host + ":" + strconv.Itoa(port)
	}
	return scheme + "://" + host
}

// -----------------------------------------------------------------------------
// Presign helpers — wrap the SDK so callers don't have to know about
// PutObjectInput / GetObjectInput.
// -----------------------------------------------------------------------------

func (s *S3) PresignPut(ctx context.Context, objectName string) (string, error) {
	req, err := s.PubPresigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectName),
	}, s3.WithPresignExpires(s.TTL))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func (s *S3) PresignGet(ctx context.Context, objectName, filename string) (string, error) {
	in := &s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectName),
	}
	if filename != "" {
		in.ResponseContentDisposition = aws.String(`attachment; filename="` + sanitizeFilename(filename) + `"`)
	}
	req, err := s.PubPresigner.PresignGetObject(ctx, in, s3.WithPresignExpires(s.TTL))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func (s *S3) Delete(ctx context.Context, objectName string) error {
	_, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectName),
	})
	return err
}

func (s *S3) Head(ctx context.Context, objectName string) (int64, error) {
	out, err := s.Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectName),
	})
	if err != nil {
		return 0, err
	}
	if out.ContentLength == nil {
		return 0, nil
	}
	return *out.ContentLength, nil
}

func sanitizeFilename(name string) string {
	// RFC 5987-style escape for header value.
	return url.PathEscape(strings.ReplaceAll(name, `"`, ""))
}
