// Package storage provides OSS (Alibaba Cloud Object Storage) upload capability.
// OSSClient is created once at startup and reused; oss.Client is concurrency-safe.
// The Uploader interface allows test injection of fakes.
package storage

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
)

// OSSClientConfig is a plain value struct with no internal package imports.
// The main.go wiring layer maps pandora.OSSConfig → OSSClientConfig.
type OSSClientConfig struct {
	BucketName       string
	ObjectPrefix     string
	Region           string
	InternalEndpoint string // internal endpoint for API calls (with -internal)
	ExternalEndpoint string // external endpoint for returned URLs (empty → derived)
	AccessKey        string
	SecretKey        string
}

// Uploader is the OSS upload interface. Handlers depend on this interface,
// not on OSSClient directly, enabling test injection of fakes.
type Uploader interface {
	UploadFile(fileName string, content []byte) (string, error)
}

// OSSClient is an Alibaba Cloud OSS client. Create once at startup, reuse
// across goroutines. The underlying oss.Client is concurrency-safe.
type OSSClient struct {
	bucketName       string
	objectPrefix     string
	accessKey        string
	secretKey        string
	internalEndpoint string
	externalEndpoint string
	ossClient        *oss.Client
}

// NewOSSClient creates an OSSClient from the given config.
// Derives externalEndpoint from internalEndpoint (strip -internal) if
// ExternalEndpoint is empty. Creates the oss.Client once for reuse.
func NewOSSClient(cfg OSSClientConfig) (*OSSClient, error) {
	if cfg.BucketName == "" {
		return nil, fmt.Errorf("BucketName is required")
	}
	if cfg.InternalEndpoint == "" {
		return nil, fmt.Errorf("InternalEndpoint is required")
	}

	externalEndpoint := cfg.ExternalEndpoint
	if externalEndpoint == "" {
		// Finance cloud (金融云) OSS has no public endpoint — the internal endpoint
		// (with -internal) is the only accessible one. Developers on VPN can access it.
		// For non-finance regions, stripping -internal gives the public endpoint.
		// When ExternalEndpoint is set (e.g. CDN domain), it overrides this.
		externalEndpoint = cfg.InternalEndpoint
	}

	credProvider := credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey)
	sdkCfg := oss.LoadDefaultConfig().
		WithCredentialsProvider(credProvider).
		WithRegion(cfg.Region).
		WithEndpoint(cfg.InternalEndpoint)
	client := oss.NewClient(sdkCfg)

	return &OSSClient{
		bucketName:       cfg.BucketName,
		objectPrefix:     cfg.ObjectPrefix,
		accessKey:        cfg.AccessKey,
		secretKey:        cfg.SecretKey,
		internalEndpoint: cfg.InternalEndpoint,
		externalEndpoint: externalEndpoint,
		ossClient:        client,
	}, nil
}

// UploadFile uploads content to OSS and returns a presigned URL (7-day expiry).
// Object path: {objectPrefix}/{fileName} (e.g. sec/abc123-report.html)
// ACL: Private (only accessible via presigned URL with auth params)
// Presigned URL format: https://bucket.endpoint/object?OSSAccessKeyId=...&Expires=...&Signature=...
// ContentType: detected by file extension (.html→text/html, .pdf→application/pdf)
// Timeout: 60 seconds via context
// Report is stored permanently; only the URL signature expires after 7 days.
func (c *OSSClient) UploadFile(fileName string, content []byte) (string, error) {
	objectPath := c.objectPrefix
	if !strings.HasSuffix(objectPath, "/") {
		objectPath += "/"
	}
	objectPath += fileName

	contentType := "application/octet-stream"
	if strings.HasSuffix(fileName, ".html") {
		contentType = "text/html"
	} else if strings.HasSuffix(fileName, ".pdf") {
		contentType = "application/pdf"
	}

	fileSize := int64(len(content))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	putRequest := &oss.PutObjectRequest{
		Bucket:        oss.Ptr(c.bucketName),
		Key:           oss.Ptr(objectPath),
		Body:          bytes.NewReader(content),
		ContentLength: &fileSize,
		ContentType:   &contentType,
		Acl:           oss.ObjectACLPrivate,
	}

	_, err := c.ossClient.PutObject(ctx, putRequest)
	if err != nil {
		return "", fmt.Errorf("oss put %s/%s failed: %w", c.bucketName, objectPath, err)
	}

	// Generate presigned URL (7-day expiry, V4 signature max).
	// Report is stored permanently on OSS; only the URL signature expires.
	presignResult, err := c.ossClient.Presign(ctx, &oss.GetObjectRequest{
		Bucket: oss.Ptr(c.bucketName),
		Key:    oss.Ptr(objectPath),
	}, oss.PresignExpires(7*24*time.Hour))
	if err != nil {
		return "", fmt.Errorf("oss presign %s/%s failed: %w", c.bucketName, objectPath, err)
	}

	return presignResult.URL, nil
}

// buildURL constructs a publicly accessible URL using the external endpoint.
// Standard OSS endpoints (aliyuncs.com): bucket name as subdomain prefix.
// CDN/custom domains: no bucket prefix (CDN origin rules handle routing).
func (c *OSSClient) buildURL(objectPath string) string {
	host := strings.TrimPrefix(c.externalEndpoint, "https://")
	host = strings.TrimPrefix(host, "http://")

	if strings.Contains(host, "aliyuncs.com") {
		return fmt.Sprintf("https://%s.%s/%s", c.bucketName, host, objectPath)
	}
	return fmt.Sprintf("https://%s/%s", host, objectPath)
}
