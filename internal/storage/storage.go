package storage

import (
	"context"
	"io"
)

// Storer is a generic interface for object storage backends.
// It abstracts storage operations to support multiple providers (S3, B2, GCS, local filesystem, etc.)
type Storage interface {
	// Upload uploads data from a reader to the specified key.
	// contentType specifies the MIME type (empty string will auto-detect).
	// metadata contains optional key-value pairs to store with the object.
	Upload(ctx context.Context, key string, body io.Reader, contentType string, metadata map[string]string) error

	// Download retrieves an object and writes it to the provided writer.
	// Returns the content type and metadata of the object.
	Download(ctx context.Context, key string, w io.Writer) (contentType string, metadata map[string]string, err error)

	// GetMetadata retrieves only the metadata for a specific object without downloading it.
	GetMetadata(ctx context.Context, key string) (map[string]string, error)

	// List returns information about all objects matching the optional prefix.
	// If prefix is empty, lists all objects in the storage.
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
}

// ObjectInfo contains metadata about a stored object.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified string
	ETag         string
	Metadata     map[string]string
}
