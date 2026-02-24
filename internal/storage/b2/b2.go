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
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/thebluefowl/burrow/internal/storage"
)

// Compile-time checks
var _ storage.Storage = (*B2Client)(nil)
var _ storage.ResumableStorage = (*B2Client)(nil)

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

// CreateMultipartUpload initiates a multipart upload and returns the upload ID.
func (c *B2Client) CreateMultipartUpload(ctx context.Context, key, contentType string, metadata map[string]string) (string, error) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	input := &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	}
	if len(metadata) > 0 {
		input.Metadata = metadata
	}
	output, err := c.client.CreateMultipartUpload(ctx, input)
	if err != nil {
		return "", fmt.Errorf("create multipart upload %s/%s: %w", c.bucket, key, err)
	}
	return *output.UploadId, nil
}

// UploadPart uploads a single part of a multipart upload.
func (c *B2Client) UploadPart(ctx context.Context, key, uploadID string, partNumber int32, body io.ReadSeeker, contentLength int64) (string, error) {
	input := &s3.UploadPartInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(partNumber),
		Body:          body,
		ContentLength: aws.Int64(contentLength),
	}
	output, err := c.client.UploadPart(ctx, input)
	if err != nil {
		return "", fmt.Errorf("upload part %d of %s/%s: %w", partNumber, c.bucket, key, err)
	}
	return *output.ETag, nil
}

// CompleteMultipartUpload finalizes a multipart upload with the given parts.
func (c *B2Client) CompleteMultipartUpload(ctx context.Context, key, uploadID string, parts []storage.CompletedUploadPart) error {
	s3Parts := make([]types.CompletedPart, len(parts))
	for i, p := range parts {
		s3Parts[i] = types.CompletedPart{
			PartNumber: aws.Int32(p.PartNumber),
			ETag:       aws.String(p.ETag),
		}
	}
	input := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(c.bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: s3Parts,
		},
	}
	_, err := c.client.CompleteMultipartUpload(ctx, input)
	if err != nil {
		return fmt.Errorf("complete multipart upload %s/%s: %w", c.bucket, key, err)
	}
	return nil
}

// AbortMultipartUpload cancels an in-progress multipart upload.
func (c *B2Client) AbortMultipartUpload(ctx context.Context, key, uploadID string) error {
	input := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(c.bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}
	_, err := c.client.AbortMultipartUpload(ctx, input)
	if err != nil {
		return fmt.Errorf("abort multipart upload %s/%s: %w", c.bucket, key, err)
	}
	return nil
}

// ListParts returns the parts that have been uploaded for a multipart upload.
func (c *B2Client) ListParts(ctx context.Context, key, uploadID string) ([]storage.CompletedUploadPart, error) {
	var parts []storage.CompletedUploadPart
	input := &s3.ListPartsInput{
		Bucket:   aws.String(c.bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}
	for {
		output, err := c.client.ListParts(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list parts %s/%s: %w", c.bucket, key, err)
		}
		for _, p := range output.Parts {
			parts = append(parts, storage.CompletedUploadPart{
				PartNumber: aws.ToInt32(p.PartNumber),
				ETag:       aws.ToString(p.ETag),
				Size:       aws.ToInt64(p.Size),
			})
		}
		if !aws.ToBool(output.IsTruncated) {
			break
		}
		input.PartNumberMarker = output.NextPartNumberMarker
	}
	return parts, nil
}

// HeadObject returns the size of an object.
func (c *B2Client) HeadObject(ctx context.Context, key string) (int64, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}
	output, err := c.client.HeadObject(ctx, input)
	if err != nil {
		return 0, fmt.Errorf("head object %s/%s: %w", c.bucket, key, err)
	}
	return aws.ToInt64(output.ContentLength), nil
}

// DownloadRange downloads a byte range of an object.
func (c *B2Client) DownloadRange(ctx context.Context, key string, w io.Writer, offset, length int64) error {
	rangeHeader := fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)
	input := &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
		Range:  aws.String(rangeHeader),
	}
	result, err := c.client.GetObject(ctx, input)
	if err != nil {
		return fmt.Errorf("range get %s/%s: %w", c.bucket, key, err)
	}
	defer result.Body.Close()
	_, err = io.Copy(w, result.Body)
	if err != nil {
		return fmt.Errorf("copy range data: %w", err)
	}
	return nil
}

// PartSize returns the configured part size in bytes.
func (c *B2Client) PartSize() int64 {
	return c.partSizeMB * 1024 * 1024
}

// GetClient returns the underlying S3 client.
func (c *B2Client) GetClient() *s3.Client {
	return c.client
}

// GetBucket returns the configured bucket name.
func (c *B2Client) GetBucket() string {
	return c.bucket
}
