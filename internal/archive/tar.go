// internal/archive/tar.go
package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Options controls how StreamTar behaves.
type Options struct {
	// Include a header for the top-level directory when srcPath is a directory.
	IncludeRoot bool
	// If true, produce deterministic output:
	// - zero timestamps
	// - zero uid/gid and owner names
	// - sort entries lexicographically
	Deterministic bool
	// Exclude is a list of glob patterns matched against the *tar path*
	// (forward-slash separated, rooted at the archive root).
	// Examples: ".git/**", "node_modules/**", "*.tmp"
	Exclude []string
	// FollowSymlinks: if true, dereference regular-file symlinks.
	// Directory symlinks are not followed (to avoid cycles); we emit a symlink header instead.
	FollowSymlinks bool
}

// StreamTar writes a tar archive of srcPath into w according to opts.
// For a file, it tars just that file. For a directory, it walks recursively.
// The archive root is the basename of srcPath (normalized).
func StreamTar(ctx context.Context, w io.Writer, srcPath string, opts Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	srcPath = filepath.Clean(srcPath)

	rootName := filepath.Base(srcPath)
	if rootName == "" || rootName == string(filepath.Separator) {
		rootName = "archive"
	}
	rootName = normalizeTarPath(rootName)

	tw := tar.NewWriter(w)
	defer tw.Close()

	info, err := os.Lstat(srcPath)
	if err != nil {
		return fmt.Errorf("stat %q: %w", srcPath, err)
	}

	// Collect entries in a slice so we can sort for determinism.
	type entry struct {
		full string      // filesystem path
		name string      // path inside tar (normalized)
		info fs.FileInfo // lstat info
	}
	var entries []entry

	emit := func(full, name string, fi fs.FileInfo) {
		entries = append(entries, entry{full: full, name: normalizeTarPath(name), info: fi})
	}

	// Build entries
	switch {
	case info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0:
		if shouldExclude(rootName, opts.Exclude) {
			return nil
		}
		emit(srcPath, rootName, info)

	case info.IsDir():
		if opts.IncludeRoot && !shouldExclude(rootName, opts.Exclude) {
			emit(srcPath, rootName, info)
		}
		err = filepath.WalkDir(srcPath, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Skip the root itself; we added it above if IncludeRoot=true
			if filepath.Clean(p) == srcPath {
				return nil
			}

			fi, err := d.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(srcPath, p)
			if err != nil {
				return err
			}
			// name inside tar is rootName/rel
			nameInTar := filepath.Join(rootName, rel)
			nameInTar = normalizeTarPath(nameInTar)

			if shouldExclude(nameInTar, opts.Exclude) {
				if fi.IsDir() {
					// Skip walking this directory
					return fs.SkipDir
				}
				return nil
			}
			emit(p, nameInTar, fi)
			return nil
		})
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported file type: %s", srcPath)
	}

	// Deterministic: sort by name (tar path)
	if opts.Deterministic {
		sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	}

	// Write headers + contents
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := writeEntry(tw, e.full, e.name, e.info, opts); err != nil {
			return err
		}
	}

	return nil
}

// ---- helpers ----

func writeEntry(tw *tar.Writer, fullPath, nameInTar string, info fs.FileInfo, opts Options) error {
	mode := info.Mode()

	switch {
	case mode.IsRegular():
		// If following symlinks and this file is actually a symlink to a regular file, dereference.
		if opts.FollowSymlinks && (mode&os.ModeSymlink) != 0 {
			target, err := os.Readlink(fullPath)
			if err == nil {
				// Try stat on the target
				if st, err2 := os.Stat(resolveSymlink(fullPath, target)); err2 == nil && st.Mode().IsRegular() {
					return addFile(tw, resolveSymlink(fullPath, target), nameInTar, st, opts)
				}
			}
			// fall through to symlink header if not a regular file target
		}
		return addFile(tw, fullPath, nameInTar, info, opts)

	case mode.IsDir():
		return addDirHeader(tw, nameInTar, info, opts)

	case mode&os.ModeSymlink != 0:
		return addSymlink(tw, fullPath, nameInTar, info, opts)

	default:
		// Skip devices, sockets, FIFOs, etc.
		return nil
	}
}

func addFile(tw *tar.Writer, fullPath, nameInTar string, info fs.FileInfo, opts Options) error {
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	applyHeaderFixups(hdr, nameInTar, info, opts)

	f, err := os.Open(fullPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func addDirHeader(tw *tar.Writer, nameInTar string, info fs.FileInfo, opts Options) error {
	name := nameInTar
	if !strings.HasSuffix(name, "/") {
		name += "/"
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	applyHeaderFixups(hdr, name, info, opts)
	return tw.WriteHeader(hdr)
}

func addSymlink(tw *tar.Writer, fullPath, nameInTar string, info fs.FileInfo, opts Options) error {
	target, err := os.Readlink(fullPath)
	if err != nil {
		return err
	}
	// Linkname in tar must be forward-slash normalized and not absolute/drive.
	target = normalizeLinkTarget(target)

	hdr, err := tar.FileInfoHeader(info, target)
	if err != nil {
		return err
	}
	applyHeaderFixups(hdr, nameInTar, info, opts)
	return tw.WriteHeader(hdr)
}

func applyHeaderFixups(hdr *tar.Header, nameInTar string, info fs.FileInfo, opts Options) {
	// Normalize path (no leading slashes)
	hdr.Name = strings.TrimLeft(normalizeTarPath(nameInTar), "/")

	// Only preserve permission bits; drop sticky/setuid/setgid from headers.
	hdr.Mode = int64(info.Mode().Perm())

	if opts.Deterministic {
		zero := time.Unix(0, 0).UTC()
		hdr.ModTime = zero
		hdr.AccessTime = zero
		hdr.ChangeTime = zero
		hdr.Uid = 0
		hdr.Gid = 0
		hdr.Uname = ""
		hdr.Gname = ""
		// Some platforms put PAX extended headers; we avoid setting extra fields.
	}
}

func normalizeTarPath(p string) string {
	// Convert OS separators to forward slashes
	if filepath.Separator != '/' {
		p = strings.ReplaceAll(p, string(filepath.Separator), "/")
	}
	// Remove Windows drive letters (C:, D:)
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}
	// Trim any leading slashes
	p = strings.TrimLeft(p, "/\\")
	return p
}

func normalizeLinkTarget(target string) string {
	// For absolute targets, keep as-is but strip drive letters on Windows.
	if filepath.IsAbs(target) {
		t := target
		if runtime.GOOS == "windows" && len(t) >= 2 && t[1] == ':' {
			t = t[2:]
		}
		return normalizeTarPath(t)
	}
	// Relative target: keep relative form, but normalize separators.
	return normalizeTarPath(target)
}

func resolveSymlink(base, target string) string {
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Clean(filepath.Join(filepath.Dir(base), target))
}

func shouldExclude(nameInTar string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	// nameInTar is normalized with forward slashes.
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		p := pat
		// Support "**" by a simple expansion: check prefix/contains forms
		// and also exact/glob via path.Match semantics.
		if matchGlob(p, nameInTar) {
			return true
		}
		// Also try matching against the base name for patterns like "*.tmp"
		if matchGlob(p, filepath.Base(nameInTar)) {
			return true
		}
	}
	return false
}

// matchGlob provides minimal glob matching with '*' and '?' and supports
// '**' to span directories by translating to a simple contains check.
func matchGlob(pattern, s string) bool {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	s = strings.ReplaceAll(s, "\\", "/")

	// Fast path for "**" at ends.
	if strings.HasPrefix(pattern, "**/") {
		pattern = strings.TrimPrefix(pattern, "**/")
		if hasSuffixGlob(pattern) {
			// fallback to filepath.Match later
		} else if strings.HasSuffix(s, pattern) {
			return true
		}
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}

	// Use filepath.Match for standard globbing (*, ?)
	ok, _ := filepath.Match(pattern, s)
	return ok
}

func hasSuffixGlob(p string) bool {
	return strings.ContainsAny(p, "*?")
}

// Convenience: small wrapper for simple use without exclusions.
func StreamTarSimple(w io.Writer, srcPath string) error {
	return StreamTar(context.Background(), w, srcPath, Options{})
}

// ValidateOptions can be called by callers if desired.
func ValidateOptions(opts Options) error {
	for _, p := range opts.Exclude {
		if strings.TrimSpace(p) == "" {
			return errors.New("exclude patterns must not be empty")
		}
	}
	return nil
}

func ExtractTar(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Clean up paths
		name := filepath.Clean(hdr.Name)
		if strings.HasPrefix(name, "..") {
			return fmt.Errorf("illegal path: %s", name)
		}
		target := filepath.Join(destDir, name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			// Ensure parent dir exists
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.CopyN(f, tr, hdr.Size); err != nil && err != io.EOF {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()

		case tar.TypeSymlink:
			// Ensure parent dir exists
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("symlink %s -> %s: %w", target, hdr.Linkname, err)
			}

		case tar.TypeLink:
			// Hard link — rarely used, but handle it.
			linkTarget := filepath.Join(destDir, hdr.Linkname)
			if err := os.Link(linkTarget, target); err != nil {
				return fmt.Errorf("hardlink %s -> %s: %w", target, linkTarget, err)
			}

		default:
			// Skip other types
			continue
		}
	}
	return nil
}
