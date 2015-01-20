// Package archive packs files into a gzipped tarball with maximum
// compression. It will only pack regular files and directories.
package archive

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kisom/sbuf"
)

// Verbose determines whether to print paths as they are packed.
var Verbose = true

// PackFiles walks the specified paths and archives them; the resulting
// archive is gzipped with maximum compression.
func PackFiles(paths []string) ([]byte, error) {
	// Create a buffer to write our archive to.
	buf := sbuf.NewBuffer(0)

	zbuf, err := gzip.NewWriterLevel(buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	// Create a new tar archive.
	tw := tar.NewWriter(zbuf)

	for _, walkPath := range paths {
		walker := func(path string, info os.FileInfo, err error) error {
			if info == nil {
				return fmt.Errorf("filecrypt: %s could not be read", path)
			}

			if !info.Mode().IsDir() && !info.Mode().IsRegular() {
				return errors.New("filecrypt: failed to compress " + path)
			}

			if Verbose {
				fmt.Println("Pack file", path)
			}

			filePath := filepath.Clean(path)
			hdr, err := tar.FileInfoHeader(info, filePath)
			if err != nil {
				return err
			}
			hdr.Name = filePath

			if err = tw.WriteHeader(hdr); err != nil {
				return err
			}

			if info.Mode().IsRegular() {
				file, err := os.Open(path)
				if err != nil {
					return err
				}

				_, err = io.Copy(tw, file)
				file.Close()
				return err
			}
			return nil

		}
		err := filepath.Walk(walkPath, walker)
		if err != nil {
			return nil, err
		}

	}

	tw.Close()
	zbuf.Close()

	return buf.Bytes(), nil
}

// UnpackFiles decompresses and unarchives the gzipped tarball passed in
// as data and uncompresses it to the top-level directory given. If
// unpack is false, only file names will be listed.
func UnpackFiles(in []byte, top string, unpack bool) error {
	buf := sbuf.NewBufferFrom(in)
	zbuf, err := gzip.NewReader(buf)
	if err != nil {
		return err
	}
	defer zbuf.Close()

	tr := tar.NewReader(zbuf)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		if Verbose || !unpack {
			fmt.Println(hdr.Name)
		}

		if !unpack {
			continue
		}

		filePath := filepath.Clean(filepath.Join(top, hdr.Name))
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.Create(filePath)
			if err != nil {
				return err
			}

			_, err = io.Copy(file, tr)
			if err != nil {
				return err
			}

			err = file.Chmod(os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
		case tar.TypeDir:
			err = os.MkdirAll(filePath, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
		}
	}
}
