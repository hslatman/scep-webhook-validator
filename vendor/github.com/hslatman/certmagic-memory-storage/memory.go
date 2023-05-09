package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"

	"github.com/caddyserver/certmagic"
	"github.com/spf13/afero"
	"oya.to/namedlocker"
)

// Memory is an in-memory implementation of certmagic.Storage
// backed by github.com/spf13/afero.
type Memory struct {
	fs afero.Fs
	ls namedlocker.Store
}

func New(opts ...Option) *Memory {
	m := &Memory{
		fs: afero.NewMemMapFs(),
	}
	for _, applyTo := range opts {
		applyTo(m)
	}
	return m
}

func (m *Memory) Lock(ctx context.Context, name string) error {
	m.ls.Lock(name)
	return nil
}

func (m *Memory) Unlock(ctx context.Context, name string) error {
	return m.ls.TryUnlock(name)
}

func (m *Memory) Store(ctx context.Context, key string, value []byte) error {
	filename := m.filename(key)
	if filename == "" {
		return errors.New("empty key not allowed")
	}
	if err := m.fs.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return fmt.Errorf("failed making directories: %w", err)
	}
	return afero.WriteFile(m.fs, filename, value, 0600)
}

func (m *Memory) Load(ctx context.Context, key string) ([]byte, error) {
	filename := m.filename(key)
	return afero.ReadFile(m.fs, filename)
}

func (m *Memory) Exists(ctx context.Context, key string) bool {
	_, err := m.fs.Stat(m.filename(key))
	return !errors.Is(err, fs.ErrNotExist)
}

func (m *Memory) Delete(ctx context.Context, key string) error {
	filename := m.filename(key)
	return m.fs.Remove(filename)
}

func (m *Memory) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var result []string
	walkPrefix := m.filename(prefix)
	walkFn := func(fpath string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info == nil {
			return fmt.Errorf("file info for %q is nil", fpath)
		}
		if fpath == walkPrefix {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		suffix, err := filepath.Rel(walkPrefix, fpath)
		if err != nil {
			return fmt.Errorf("failed making path %q relative: %w", fpath, err)
		}
		result = append(result, path.Join(prefix, suffix))
		if !recursive && info.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}

	err := afero.Walk(m.fs, walkPrefix, walkFn)
	return result, err
}

func (m *Memory) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	filename := m.filename(key)
	result := certmagic.KeyInfo{}
	info, err := m.fs.Stat(filename)
	if err != nil {
		return result, fmt.Errorf("failed to stat file %q: %w", filename, err)
	}
	result.Key = key
	result.IsTerminal = !info.IsDir()
	result.Modified = info.ModTime()
	result.Size = info.Size()
	return result, nil
}

func (m *Memory) filename(key string) string {
	return key
}

var _ certmagic.Storage = (*Memory)(nil)
