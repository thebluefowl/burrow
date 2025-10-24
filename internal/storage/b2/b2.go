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
	"github.com/thebluefowl/burrow/internal/storage"
)

// Compile-time check to ensure B2Client implements storage.Storage interface
var _ storage.Storage = (*B2Client)(nil)

// B2Client encapsulates a Backblaze B2 S3-compatible client and default settings.
type B2Client struct {
	client      *s3.Client
	bucket      string
	partSizeMB  int64
	concurrency int
}

// Config holds options to initialize the uploader.
type Opts struct {
	Bucket      string
	Region      string
	Endpoint    string
	AccessKey   string
	SecretKey   string
	PartSizeMB  int64 // default 16
	Concurrency int   // default 4
}

// NewB2Client builds a new client configured for Backblaze B2.
func New(ctx context.Context, opts *Opts) (*B2Client, error) {
	if opts.PartSizeMB <= 0 {
		opts.PartSizeMB = 16
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}

	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(opts.Region),
		config.WithBaseEndpoint(opts.Endpoint),
	}
	if opts.AccessKey != "" && opts.SecretKey != "" {
		loadOpts = append(loadOpts,
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey, "")))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.UsePathStyle = true })

	return &B2Client{
		client:      client,
		bucket:      opts.Bucket,
		partSizeMB:  opts.PartSizeMB,
		concurrency: opts.Concurrency,
	}, nil
}

// Upload uploads data from a reader to the specified key with optional metadata.
func (c *B2Client) Upload(ctx context.Context, key string, body io.Reader, contentType string, metadata map[string]string) error {
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

	_, err := uploader.Upload(ctx, input)
	if err != nil {
		return fmt.Errorf("upload %s/%s: %w", c.bucket, key, err)
	}
	return nil
}

// UploadFile opens a local file and uploads it.
func (c *B2Client) UploadFile(ctx context.Context, filePath, key string, metadata map[string]string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file %s: %w", filePath, err)
	}
	defer f.Close()
	return c.Upload(ctx, key, f, "", metadata)
}

// Download retrieves an object and writes it to the provided writer.
// Returns the content type and metadata of the object.
func (c *B2Client) Download(ctx context.Context, key string, w io.Writer) (contentType string, metadata map[string]string, err error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}

	result, err := c.client.GetObject(ctx, input)
	if err != nil {
		return "", nil, fmt.Errorf("get object %s/%s: %w", c.bucket, key, err)
	}
	defer result.Body.Close()

	_, err = io.Copy(w, result.Body)
	if err != nil {
		return "", nil, fmt.Errorf("copy object data: %w", err)
	}

	ct := ""
	if result.ContentType != nil {
		ct = *result.ContentType
	}

	return ct, result.Metadata, nil
}

// List lists all objects in the bucket with optional prefix filtering.
// It automatically handles pagination to retrieve all objects.
// Note: ListObjectsV2 does not return metadata. Use GetMetadata for individual objects.
func (c *B2Client) List(ctx context.Context, prefix string) ([]storage.ObjectInfo, error) {
	var objects []storage.ObjectInfo

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
			etag := ""
			if obj.ETag != nil {
				etag = *obj.ETag
			}
			objects = append(objects, storage.ObjectInfo{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: lastMod,
				ETag:         etag,
			})
		}
	}

	return objects, nil
}

// GetMetadata retrieves metadata for a specific object without downloading it.
func (c *B2Client) GetMetadata(ctx context.Context, key string) (map[string]string, error) {
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
