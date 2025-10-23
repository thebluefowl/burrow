// internal/b2/b2.go
package b2

import (
	"context"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// B2Client encapsulates a Backblaze B2 S3-compatible client and default settings.
type B2Client struct {
	client      *s3.Client
	bucket      string
	partSizeMB  int64
	concurrency int
}

// Config holds options to initialize the uploader.
type Config struct {
	Bucket      string
	Region      string
	Endpoint    string
	AccessKey   string
	SecretKey   string
	PartSizeMB  int64 // default 16
	Concurrency int   // default 4
}

// NewB2Client builds a new client configured for Backblaze B2.
func NewB2Client(ctx context.Context, cfg Config) (*B2Client, error) {
	if cfg.PartSizeMB <= 0 {
		cfg.PartSizeMB = 16
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}

	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
		config.WithBaseEndpoint(cfg.Endpoint),
	}
	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		loadOpts = append(loadOpts,
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.UsePathStyle = true })

	return &B2Client{
		client:      client,
		bucket:      cfg.Bucket,
		partSizeMB:  cfg.PartSizeMB,
		concurrency: cfg.Concurrency,
	}, nil
}

// Upload uploads data from a reader to the specified key with optional metadata.
func (c *B2Client) Upload(ctx context.Context, key string, body io.Reader, contentType string, metadata map[string]string) (*manager.UploadOutput, error) {
	if contentType == "" {
		if ext := filepath.Ext(key); ext != "" {
			contentType = mime.TypeByExtension(ext)
		}
		if contentType == "" {
			contentType = "application/octet-stream"
		}
	}

	uploader := manager.NewUploader(c.client, func(m *manager.Uploader) {
		m.PartSize = c.partSizeMB * 1024 * 1024
		m.Concurrency = c.concurrency
	})

	input := &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String(contentType),
	}
	if len(metadata) > 0 {
		input.Metadata = metadata
	}

	out, err := uploader.Upload(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("upload %s/%s: %w", c.bucket, key, err)
	}
	return out, nil
}

// UploadFile opens a local file and uploads it.
func (c *B2Client) UploadFile(ctx context.Context, filePath, key string, metadata map[string]string) (*manager.UploadOutput, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", filePath, err)
	}
	defer f.Close()
	return c.Upload(ctx, key, f, "", metadata)
}

// ObjectInfo represents information about a single object in the bucket.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified *string
	ETag         *string
	Metadata     map[string]string
}

// ListObjects lists all objects in the bucket with optional prefix filtering.
// It automatically handles pagination to retrieve all objects.
// Note: ListObjectsV2 does not return metadata. Use GetObjectMetadata for individual objects.
func (c *B2Client) ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var objects []ObjectInfo

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(c.bucket),
	}
	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}

	paginator := s3.NewListObjectsV2Paginator(c.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list objects in %s: %w", c.bucket, err)
		}

		for _, obj := range page.Contents {
			lastMod := ""
			if obj.LastModified != nil {
				lastMod = obj.LastModified.String()
			}
			objects = append(objects, ObjectInfo{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: &lastMod,
				ETag:         obj.ETag,
			})
		}
	}

	return objects, nil
}

// GetObjectMetadata retrieves metadata for a specific object.
func (c *B2Client) GetObjectMetadata(ctx context.Context, key string) (map[string]string, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}

	output, err := c.client.HeadObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("get metadata for %s/%s: %w", c.bucket, key, err)
	}

	return output.Metadata, nil
}

// GetClient returns the underlying S3 client.
func (c *B2Client) GetClient() *s3.Client {
	return c.client
}

// GetBucket returns the configured bucket name.
func (c *B2Client) GetBucket() string {
	return c.bucket
}
