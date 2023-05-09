package storage

import "github.com/spf13/afero"

type Option func(m *Memory)

func WithFS(fs afero.Fs) Option {
	return func(m *Memory) {
		m.fs = fs
	}
}
