// Test cases for Go symlink-follow rules
package main

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type Repository struct {
	Path string
}

// === TRUE POSITIVES: go-repo-write-no-symlink-check ===

func (r *Repository) VulnerableUpdate(path string, content []byte) error {
	fullPath := filepath.Join(r.Path, path)
	if !strings.HasPrefix(fullPath, r.Path) {
		return errors.New("traversal")
	}
	// ruleid: go-repo-write-no-symlink-check
	return os.WriteFile(fullPath, content, 0644)
}

func (r *Repository) VulnerableIoutil(path string, content []byte) error {
	fullPath := filepath.Join(r.Path, path)
	// ruleid: go-repo-write-no-symlink-check
	return ioutil.WriteFile(fullPath, content, 0644)
}

func (r *Repository) VulnerableCreate(path string) (*os.File, error) {
	fullPath := filepath.Join(r.Path, path)
	// ruleid: go-repo-write-no-symlink-check
	return os.Create(fullPath)
}

// === TRUE NEGATIVES: go-repo-write-no-symlink-check ===

func (r *Repository) SafeWithLstat(path string, content []byte) error {
	fullPath := filepath.Join(r.Path, path)
	info, err := os.Lstat(fullPath)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink not allowed")
	}
	// ok: go-repo-write-no-symlink-check
	return os.WriteFile(fullPath, content, 0644)
}

func (r *Repository) SafeWithEval(path string, content []byte) error {
	fullPath := filepath.Join(r.Path, path)
	realPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return err
	}
	// ok: go-repo-write-no-symlink-check
	return os.WriteFile(realPath, content, 0644)
}

// === TRUE POSITIVES: go-write-after-join-audit ===

func vulnerableWriteAfterJoin(base, user string, data []byte) error {
	fullPath := filepath.Join(base, user)
	// ruleid: go-write-after-join-audit
	return os.WriteFile(fullPath, data, 0644)
}

func vulnerableIoutilAfterJoin(base, user string, data []byte) error {
	fullPath := filepath.Join(base, user)
	// ruleid: go-write-after-join-audit
	return ioutil.WriteFile(fullPath, data, 0644)
}

// === TRUE NEGATIVES: go-write-after-join-audit ===

func safeWriteWithLstat(base, user string, data []byte) error {
	fullPath := filepath.Join(base, user)
	info, err := os.Lstat(fullPath)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink")
	}
	// ok: go-write-after-join-audit
	return os.WriteFile(fullPath, data, 0644)
}

func safeWriteWithEval(base, user string, data []byte) error {
	fullPath := filepath.Join(base, user)
	realPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return err
	}
	// ok: go-write-after-join-audit
	return os.WriteFile(realPath, data, 0644)
}
