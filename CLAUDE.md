# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Burrow is an encrypted backup tool for Backblaze B2, written in Go. It provides end-to-end encryption (ChaCha20-Poly1305), Zstd compression, and streaming upload/download via the S3-compatible API.

## Build and Test Commands

```bash
go build -o burrow ./cmd/burrow    # Build the binary
go test ./...                       # Run all tests
go test -v ./internal/enc           # Run encryption tests (the main test suite)
go test -short ./...                # Skip long-running tests
go test -bench=. ./internal/enc     # Run benchmarks
```

There is no Makefile. Standard `go build`/`go test` workflow.

## Architecture

### Data Pipeline

Upload and download use a streaming pipeline pattern (`internal/pipeline`) that wires stages together with `io.Pipe`:

**Upload:** Archive (tar) → Compress (zstd) → Encrypt (AEAD) → Upload (S3 multipart)
**Download:** Download → Decrypt → Decompress → Extract (tar)

Pipeline stages run concurrently with automatic error propagation and pipe cleanup.

### Key Modules

- **`internal/enc`** — Core encryption. ChaCha20-Poly1305 AEAD with chunked streaming (4MB default chunks). HKDF-SHA256 derives per-object data keys from a master key. Age library handles config encryption (scrypt) and envelope encryption (X25519). This is the only package with tests.
- **`internal/config`** — Encrypted config stored at `~/.config/burrow/config.enc`. Contains B2 credentials, master key, and age keypair. Encrypted with age scrypt (password-based).
- **`internal/envelope`** — Per-upload metadata (encryption params, checksums, compression info). Age-encrypted with the user's X25519 public key and stored as `keys/{objectID}.envelope` in B2.
- **`internal/index`** — Local encrypted index (`~/.config/burrow/index.enc`) for fast file listing without B2 API calls.
- **`internal/storage`** — `Storage` interface with B2 implementation using AWS SDK v2 S3 client. Supports multipart upload (16MB parts, 4 concurrent workers).
- **`internal/upload`** and **`internal/download`** — Orchestrate the full pipeline including envelope handling and progress display.
- **`internal/archive`** — Deterministic tar creation (zeroed timestamps, sorted entries) with symlink handling and exclusion patterns.
- **`internal/compress`** — Zstd compression with auto mode (only compresses if >5% savings).

### CLI Structure (Cobra)

Entry point is `cmd/burrow/main.go`. Commands are registered in `cmd/burrow/root.go`:
- `upload <file-or-dir>` — encrypt and upload
- `download <object-id> <dest>` — download and decrypt (flag: `--extract/-x`)
- `list` — show uploaded files from local index
- `index` — rebuild local index from B2 envelopes
- `config update` — update B2 credentials
- `config export` — export encrypted config as base64 (for backup)
- `config restore` — restore config from a base64 export

### Key Derivation Chain

```
User Password → Age Scrypt Identity → Config Decryption
Config contains: Master Key (32 random bytes) + Age X25519 Keypair
Master Key + ObjectID → HKDF-SHA256 → Per-object Data Key (ChaCha20-Poly1305)
```

Each upload gets a unique KSUID as its ObjectID and a random nonce base. Per-chunk nonces are derived from the base nonce + chunk index to prevent reuse.

## Dependencies

- Go 1.24+ required
- `filippo.io/age` for age encryption, `golang.org/x/crypto` for ChaCha20-Poly1305
- `aws/aws-sdk-go-v2` for B2 (S3-compatible), `spf13/cobra` for CLI
- `klauspost/compress` for zstd, `segmentio/ksuid` for object IDs
