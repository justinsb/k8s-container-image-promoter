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

package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"k8s.io/klog"
)

type FilestorePromoter struct {
	Source *Filestore
	Dest   *Filestore

	Files []*File

	// DryRun (if set) will not perform operations, but print them instead
	DryRun bool

	// Out is the destination for "normal" output (such as dry-run)
	Out io.Writer

	// UseServiceAccount should be set to true to enable us to assume service accounts
	UseServiceAccount bool
}

// syncFileInfo holds information about a file during the synchronization operation
type syncFileInfo struct {
	RelativePath string
	AbsolutePath string
	MD5          string
	Size         int64

	filestore syncFilestore
}

// gcloudTokenSource implements oauth2.TokenSource
type gcloudTokenSource struct {
	mutex          sync.Mutex
	ServiceAccount string
}

// Token implements TokenSource.Token
func (s *gcloudTokenSource) Token() (*oauth2.Token, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	klog.Infof("getting service-account-token for %q", s.ServiceAccount)

	token, err := GetServiceAccountToken(s.ServiceAccount, true)
	if err != nil {
		klog.Warningf("failed to get service-account-token for %q: %v", s.ServiceAccount, err)
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: string(token),
	}, nil
}

type syncFilestore interface {
	// OpenReader opens an io.ReadCloser for the specified file
	OpenReader(ctx context.Context, name string) (io.ReadCloser, error)

	// UploadFile uploads a local file to the specified destination
	UploadFile(ctx context.Context, dest string, localFile string) error

	// ListFiles returns all the all artifacts in the filestore, recursively.
	ListFiles(ctx context.Context) (map[string]*syncFileInfo, error)
}

type gcsSyncFilestore struct {
	filestore *Filestore
	client    *storage.Client
	bucket    string
	prefix    string
}

func openFilestore(ctx context.Context, filestore *Filestore, useServiceAccount bool) (syncFilestore, error) {
	u, err := url.Parse(filestore.Base)
	if err != nil {
		return nil, fmt.Errorf("error parsing filestore base %q: %v", filestore.Base, err)
	}

	if u.Scheme != "gs" {
		return nil, fmt.Errorf("only gs:// (Google Cloud Storage) filestores are currently supported")
	}

	var opts []option.ClientOption
	if useServiceAccount && filestore.ServiceAccount != "" {
		opts = append(opts, option.WithTokenSource(&gcloudTokenSource{ServiceAccount: filestore.ServiceAccount}))
	} else {
		opts = append(opts, option.WithoutAuthentication())
	}

	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("error building GCS client: %v", err)
	}

	prefix := strings.TrimPrefix(u.Path, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	bucket := u.Host

	s := &gcsSyncFilestore{
		filestore: filestore,
		client:    client,
		bucket:    bucket,
		prefix:    prefix,
	}
	return s, nil
}

// OpenReader opens an io.ReadCloser for the specified file
func (s *gcsSyncFilestore) OpenReader(ctx context.Context, name string) (io.ReadCloser, error) {
	absolutePath := s.prefix + name
	return s.client.Bucket(s.bucket).Object(absolutePath).NewReader(ctx)
}

// UploadFile uploads a local file to the specified destination
func (s *gcsSyncFilestore) UploadFile(ctx context.Context, dest string, localFile string) error {
	absolutePath := s.prefix + dest

	gcsUrl := "gs://" + s.bucket + "/" + absolutePath

	in, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("error opening %q: %v", localFile, err)
	}
	defer in.Close()

	klog.Infof("uploading to %s", gcsUrl)

	out := s.client.Bucket(s.bucket).Object(absolutePath).NewWriter(ctx)

	if _, err := io.Copy(out, in); err != nil {
		out.Close() // best effort
		// TODO: Try to delete the possibly partially written file?
		return fmt.Errorf("error uploading to %q: %v", gcsUrl, err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("error uploading to %q: %v", gcsUrl, err)
	}

	return nil
}

// ListFiles returns all the all artifacts in the filestore, recursively.
func (s *gcsSyncFilestore) ListFiles(ctx context.Context) (map[string]*syncFileInfo, error) {
	files := make(map[string]*syncFileInfo)

	q := &storage.Query{Prefix: s.prefix}
	klog.Infof("listing files in bucket %s with prefix %s", s.bucket, s.prefix)
	it := s.client.Bucket(s.bucket).Objects(ctx, q)
	for {
		obj, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error listing objects in %q: %v", s.filestore.Base, err)
		}
		name := obj.Name
		if !strings.HasPrefix(name, s.prefix) {
			return nil, fmt.Errorf("found object %q without prefix %q", name, s.prefix)
		}

		file := &syncFileInfo{}
		file.AbsolutePath = "gs://" + s.bucket + "/" + obj.Name
		file.RelativePath = strings.TrimPrefix(name, s.prefix)
		if obj.MD5 == nil {
			return nil, fmt.Errorf("MD5 not set on file %q", file.AbsolutePath)
		} else {
			file.MD5 = hex.EncodeToString(obj.MD5)
		}
		file.Size = obj.Size
		file.filestore = s

		files[file.RelativePath] = file
	}

	return files, nil
}

// syncFileOp defines a synchronization operation
type syncFileOp interface {
	Run(ctx context.Context) error
}

// computeNeededOperations determines the list of files that need to be copied
func (p *FilestorePromoter) computeNeededOperations(source, dest map[string]*syncFileInfo, destFilestore syncFilestore) ([]syncFileOp, error) {
	var ops []syncFileOp

	for _, f := range p.Files {
		relativePath := f.Name
		sourceFile := source[relativePath]
		if sourceFile == nil {
			// TODO: Should this be a warning?
			absolutePath := joinFilepath(p.Source, relativePath)
			return nil, fmt.Errorf("file %q not found in source (%q)", relativePath, absolutePath)
		}

		destFile := dest[relativePath]
		if destFile == nil {
			destFile = &syncFileInfo{}
			destFile.RelativePath = sourceFile.RelativePath
			destFile.AbsolutePath = joinFilepath(p.Dest, sourceFile.RelativePath)
			destFile.filestore = destFilestore
			ops = append(ops, &copyFileOp{
				Source:       sourceFile,
				Dest:         destFile,
				ManifestFile: f,
			})
			continue
		}

		changed := false
		if destFile.MD5 != sourceFile.MD5 {
			klog.Warningf("MD5 mismatch on source %q vs dest %q: %q vs %q",
				sourceFile.AbsolutePath,
				destFile.AbsolutePath,
				sourceFile.MD5,
				destFile.MD5)
			changed = true
		}

		if destFile.Size != sourceFile.Size {
			klog.Warningf("Size mismatch on source %q vs dest %q: %d vs %d",
				sourceFile.AbsolutePath,
				destFile.AbsolutePath,
				sourceFile.Size,
				destFile.Size)
			changed = true
		}

		if !changed {
			klog.V(2).Infof("metadata match for %q", destFile.AbsolutePath)
			continue
		}
		ops = append(ops, &copyFileOp{
			Source:       sourceFile,
			Dest:         destFile,
			ManifestFile: f,
		})
	}

	return ops, nil
}

func joinFilepath(filestore *Filestore, relativePath string) string {
	s := strings.TrimSuffix(filestore.Base, "/")
	s += "/"
	s += strings.TrimPrefix(relativePath, "/")
	return s
}

// Promote copies files from the Source Filestore to the Dest Filestore
// If DryRun is set, it merely logs the operations
func (p *FilestorePromoter) Promote(ctx context.Context) ([]syncFileOp, error) {
	out := p.Out
	if out == nil {
		out = os.Stdout
	}

	sourceFilestore, err := openFilestore(ctx, p.Source, p.UseServiceAccount)
	if err != nil {
		return nil, err
	}
	destFilestore, err := openFilestore(ctx, p.Dest, p.UseServiceAccount)
	if err != nil {
		return nil, err
	}

	sourceFiles, err := sourceFilestore.ListFiles(ctx)
	if err != nil {
		return nil, err
	}

	destFiles, err := destFilestore.ListFiles(ctx)
	if err != nil {
		return nil, err
	}

	ops, err := p.computeNeededOperations(sourceFiles, destFiles, destFilestore)
	if err != nil {
		return nil, err
	}

	var done []syncFileOp
	for _, op := range ops {
		if p.DryRun {
			if _, err := fmt.Fprintf(out, "%v\n", op); err != nil {
				return nil, err
			}
		} else {
			klog.Infof("running: %v", op)
			if err := op.Run(ctx); err != nil {
				return nil, err
			}
			done = append(done, op)
		}
	}

	return done, nil
}

// copyFileOp manages copying a single file
type copyFileOp struct {
	Source *syncFileInfo
	Dest   *syncFileInfo

	ManifestFile *File
}

// Run implements syncFileOp.Run
func (o *copyFileOp) Run(ctx context.Context) error {
	f, err := ioutil.TempFile("", "promoter")
	if err != nil {
		return fmt.Errorf("error creating temp file: %v", err)
	}
	tempFilename := f.Name()
	defer func() {
		if err := os.Remove(tempFilename); err != nil {
			klog.Warningf("unable to remove temp file %q: %v", tempFilename, err)
		}
	}()

	// Download to our temp file
	in, err := o.Source.filestore.OpenReader(ctx, o.Source.RelativePath)
	if err != nil {
		f.Close() // Best effort
		return fmt.Errorf("error reading %q: %v", o.Source.AbsolutePath, err)
	}
	if _, err := io.Copy(f, in); err != nil {
		f.Close() // Best effort
		return fmt.Errorf("error downloading %q: %v", o.Source.AbsolutePath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error writing temp file %q: %v", tempFilename, err)
	}

	// Verify the source hash
	sha256, err := computeSHA256ForFile(tempFilename)
	if err != nil {
		return err
	}
	if sha256 != o.ManifestFile.SHA256 {
		return fmt.Errorf("sha256 did not match for file %q: actual=%q expected=%q", o.Source.AbsolutePath, sha256, o.ManifestFile.SHA256)
	}

	// Upload to the destination
	if err := o.Dest.filestore.UploadFile(ctx, o.Dest.RelativePath, tempFilename); err != nil {
		return err
	}

	return nil
}

// String is the pretty-printer for an operation, as used by dry-run
func (o *copyFileOp) String() string {
	return fmt.Sprintf("COPY %q to %q", o.Source.AbsolutePath, o.Dest.AbsolutePath)
}

func computeSHA256ForFile(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("error re-opening temp file %q: %v", filename, err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("error hashing file %q: %v", filename, err)
	}

	sha256 := hex.EncodeToString(hasher.Sum(nil))
	return sha256, nil
}
