package ifs

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing/fstest"
)

type TestFS struct {
	workDir string
	MapFS   fstest.MapFS
}

func (o TestFS) Chdir(dir string) FS {
	return TestFS{workDir: o.joinWithWorkdir(dir), MapFS: o.MapFS}
}

func (o TestFS) joinWithWorkdir(path string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(o.workDir, path)
	}
	return path
}

func (o TestFS) Open(name string) (fs.File, error) {
	panic("unimplemented")
}

func (t TestFS) OpenFile(name string, flag int, perm fs.FileMode) (fs.File, error) {
	return nil, errors.New("not implemented")
}

func (o TestFS) Stat(name string) (fs.FileInfo, error) {
	panic("unimplemented")
}

func (t TestFS) MkdirAll(path string, perm fs.FileMode) error {
	return errors.New("not implemented")
}

func (t TestFS) Remove(name string) error {
	return errors.New("not implemented")
}
