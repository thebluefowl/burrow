# Burrow - Backblaze B2 Backup

A secure, encrypted backup tool for Backblaze B2 cloud storage. Burrow provides end-to-end encryption, compression, and efficient upload/download capabilities for your files and directories.

## Features

- 🔐 **End-to-End Encryption**: Uses ChaCha20-Poly1305 AEAD encryption with age for key management
- 📦 **Smart Compression**: Automatically compresses data when beneficial (configurable threshold)
- 🗂️ **Directory Support**: Upload entire directories as tar archives
- ☁️ **Backblaze B2 Integration**: Direct integration with Backblaze B2 cloud storage
- 🔑 **Secure Key Management**: Master password protection with PBKDF2 key derivation
- 📊 **Progress Tracking**: Real-time progress bars for upload/download operations
- 🛡️ **Cryptographic Integrity**: SHA-256 verification for data integrity
- 🚀 **Efficient Uploads**: Multi-part uploads with configurable concurrency
- 📋 **Local Index**: Fast file listing with encrypted local index (no API calls needed)
- 🔄 **Index Management**: Rebuild index from storage when needed
- ⚙️ **Configuration Management**: Update settings without re-running setup

## Installation

### Prerequisites

- Go 1.24.2 or later
- Backblaze B2 account with API credentials

### Build from Source

```bash
git clone https://github.com/thebluefowl/burrow.git
cd burrow
go build -o burrow ./cmd/burrow
```

### Install to System

```bash
go install github.com/thebluefowl/burrow/cmd/burrow@latest
```

## Quick Start

### 1. Initial Setup

On first run, Burrow will guide you through the setup process:

```bash
burrow upload /path/to/your/files
```

You'll be prompted to:

- Set a master password (used to encrypt your configuration)
- Provide Backblaze B2 credentials:
  - Key ID
  - Application Key
  - Bucket Name
  - Region (default: us-west-002)

### 2. Upload Files

```bash
# Upload a single file
burrow upload document.pdf

# Upload a directory
burrow upload /home/user/documents
```

### 3. List Your Backups

```bash
# List all uploaded files with their object IDs and names
burrow list
```

This shows all your uploaded files with their object IDs, original file names, and upload dates. The list is stored locally in an encrypted index file, so it's fast and doesn't require API calls.

### 4. Download Files

```bash
# Download and extract to directory
burrow download <object-id> /path/to/destination --extract

# Download as encrypted file
burrow download <object-id> /path/to/destination
```

**Tip**: Use `burrow list` to find the object ID of the file you want to download.

## Usage

### Commands

#### `upload <file-or-directory>`

Encrypts and uploads a file or directory to Backblaze B2.

```bash
burrow upload /path/to/file
burrow upload /path/to/directory
```

**Features:**

- Automatically creates tar archives for directories
- Applies compression when beneficial (>5% size reduction)
- Generates unique object IDs for each upload
- Shows real-time progress during upload

#### `list`

Lists all uploaded files from your local encrypted index.

```bash
burrow list
```

**Features:**

- Fast listing (reads from local encrypted index, no API calls)
- Shows object ID, file name, and upload date
- Automatically updated on each upload

#### `index`

Rebuilds the local index by scanning all envelope files in storage.

```bash
burrow index
```

**Use when:**

- Local index file is deleted or corrupted
- Index is out of sync with storage
- Setting up on a new machine
- Need to verify all files are indexed

**Note**: This command makes API calls to download and decrypt envelopes, so it's slower than `list`.

#### `download <object-id> <destination>`

Downloads and decrypts files from Backblaze B2.

```bash
burrow download abc123def456 /home/user/restored
burrow download abc123def456 /home/user/restored --extract
```

**Options:**

- `--extract, -x`: Extract tar archives to destination directory

**Tip**: Use `burrow list` to find the object ID of files you want to download.

#### `config update`

Updates your Backblaze B2 configuration settings.

```bash
burrow config update
```

You can update:
- Backblaze Key ID
- Backblaze Application Key
- Bucket Name
- Region

Leave fields empty to keep current values.

#### `config export`

Exports your encrypted configuration as a base64-encoded string for backup.

```bash
burrow config export
```

Save this output somewhere safe. It contains your encrypted config (still protected by your master password).

#### `config restore`

Restores configuration from a previously exported base64 string.

```bash
burrow config restore
```

You'll be prompted to paste the exported string. If a config already exists, you'll be asked to confirm before overwriting.

## Architecture

### Encryption Pipeline

Burrow uses a multi-stage encryption pipeline:

1. **Archive**: Creates tar archive for directories
2. **Compress**: Applies compression if beneficial
3. **Encrypt**: ChaCha20-Poly1305 AEAD encryption
4. **Upload**: Multi-part upload to Backblaze B2

### Security Model

- **Master Password**: Protects configuration using PBKDF2 (100,000 iterations)
- **Data Encryption**: ChaCha20-Poly1305 AEAD with unique nonces per chunk
- **Key Derivation**: HKDF-SHA256 for data keys from master key
- **Envelope Encryption**: Age encryption for metadata using X25519 keys
- **Integrity**: SHA-256 verification for all data

### File Structure

**Storage (Backblaze B2):**
```
/data/<object-id>.enc     # Encrypted data
/keys/<object-id>.envelope # Encrypted metadata (contains file name, encryption params)
```

**Local (encrypted):**
```
~/.config/burrow/
  ├── config.enc          # Encrypted configuration
  └── index.enc           # Encrypted local index (for fast file listing)
```

The local index allows fast file listing without API calls. It's automatically updated on each upload and can be rebuilt using `burrow index` if needed.

## Configuration

Configuration is stored encrypted in `~/.config/burrow/` and includes:

- **config.enc**: Encrypted configuration file containing:
  - Backblaze B2 credentials
  - Age encryption keys
  - Master key for data encryption
  - Upload settings (region, bucket)
- **index.enc**: Encrypted local index file containing:
  - Object IDs
  - Original file names
  - Upload timestamps
  - File sizes

### Updating Configuration

You can update your configuration without re-running setup:

```bash
burrow config update
```

This allows you to change Backblaze credentials, bucket name, or region while preserving your encryption keys.

### Security Considerations

- **Master Password**: Choose a strong, unique password. Losing it means losing access to your backups
- **Key Storage**: Private keys are encrypted and stored locally
- **Network Security**: All data is encrypted before transmission
- **Backup Keys**: Consider backing up your age public key for recovery

## Development

### Project Structure

```
burrow/
├── cmd/burrow/           # CLI commands
│   ├── main.go          # Entry point
│   ├── root.go          # Root command
│   ├── upload.go        # Upload command
│   ├── download.go      # Download command
│   ├── list.go          # List command
│   ├── index.go         # Index rebuild command
│   ├── config.go        # Config command group
│   ├── update.go        # Config update command
│   ├── export.go        # Config export command
│   ├── restore.go       # Config restore command
│   └── setup.go         # Initial setup
├── internal/
│   ├── archive/       # Tar archiving
│   ├── compress/      # Compression utilities
│   ├── config/        # Configuration management
│   ├── download/      # Download pipeline
│   ├── enc/          # Encryption (AEAD, age)
│   ├── envelope/     # Metadata management
│   ├── index/        # Local index management
│   ├── pipeline/     # Processing pipeline
│   ├── progress/     # Progress tracking
│   ├── storage/      # Storage backend interface (B2)
│   └── upload/       # Upload pipeline
└── testdata/         # Test files
```

### Dependencies

- **age**: Modern encryption library for key management
- **ChaCha20-Poly1305**: AEAD encryption for data
- **Backblaze B2**: Cloud storage backend
- **Cobra**: CLI framework
- **Survey**: Interactive prompts

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions:

- Open an issue on GitHub
- Check the documentation
- Review the source code for implementation details

---

**⚠️ Important**: Always test your backup and restore process with non-critical data first. Ensure you have secure backups of your master password and age keys.
