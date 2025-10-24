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

### 3. Download Files

```bash
# Download and extract to directory
burrow download <object-id> /path/to/destination --extract

# Download as encrypted file
burrow download <object-id> /path/to/destination
```

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

#### `download <object-id> <destination>`

Downloads and decrypts files from Backblaze B2.

```bash
burrow download abc123def456 /home/user/restored
burrow download abc123def456 /home/user/restored --extract
```

**Options:**

- `--extract, -x`: Extract tar archives to destination directory

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

```
/data/<object-id>.enc     # Encrypted data
/keys/<object-id>.envelope # Encrypted metadata
```

## Configuration

Configuration is stored encrypted in `~/.config/burrow/config.enc` and includes:

- Backblaze B2 credentials
- Age encryption keys
- Master key for data encryption
- Upload settings (region, bucket)

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
├── internal/
│   ├── archive/       # Tar archiving
│   ├── compress/      # Compression utilities
│   ├── config/        # Configuration management
│   ├── download/      # Download pipeline
│   ├── enc/          # Encryption (AEAD, age)
│   ├── envelope/     # Metadata management
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
