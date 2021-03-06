/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package filepromoter

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

type fsStore struct {
	basedir string
}

// OpenReader opens an io.ReadCloser for the specified file
func (s *fsStore) OpenReader(
	ctx context.Context,
	name string) (io.ReadCloser, error) {
	p := filepath.Join(s.basedir, name)
	return os.Open(p)
}

// UploadFile uploads a local file to the specified destination
func (s *fsStore) UploadFile(
	ctx context.Context,
	dest string,
	localFile string) error {
	return fmt.Errorf("UploadFile not implemented for fsStore")
}

// ListFiles returns all the file artifacts in the filestore, recursively.
func (s *fsStore) ListFiles(
	ctx context.Context) (map[string]*syncFileInfo, error) {
	files := make(map[string]*syncFileInfo)

	basedir := s.basedir
	if !strings.HasSuffix(basedir, "/") {
		basedir += "/"
	}

	if err := filepath.Walk(basedir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !strings.HasPrefix(p, basedir) {
			return xerrors.Errorf("expected path %q to have prefix %q", p, basedir)
		}

		if info.IsDir() {
			return nil
		}

		md5, err := ComputeMD5ForFile(p)
		if err != nil {
			return xerrors.Errorf("error hashing file %q: %w", p, err)
		}

		file := &syncFileInfo{}
		file.AbsolutePath = "file://" + basedir
		file.RelativePath = strings.TrimPrefix(p, basedir)
		file.MD5 = md5
		file.Size = info.Size()
		file.filestore = s

		files[file.RelativePath] = file
		return nil
	}); err != nil {
		return nil, xerrors.Errorf("error walking path %q: %w", basedir, err)
	}

	return files, nil
}
