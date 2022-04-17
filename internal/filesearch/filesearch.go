package filesearch

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/fgmaia/securitycodescanner/internal/domain"
)

type FileSearch interface {
	Execute(ctx context.Context, path string) <-chan domain.FileScan
}

type fileSearch struct {
	maxBufferSize int
}

func NewFileSearch(maxBufferSize int) FileSearch {
	return &fileSearch{maxBufferSize: maxBufferSize}
}

func (s *fileSearch) Execute(ctx context.Context, path string) <-chan domain.FileScan {

	ch := make(chan domain.FileScan, s.maxBufferSize)

	go func(c chan domain.FileScan) {
		defer close(ch)
		err := s.readFiles(ctx, ch, path)
		if err != nil {
			ch <- domain.FileScan{Error: err}
		}
	}(ch)

	return ch
}

func (s *fileSearch) readFiles(ctx context.Context, ch chan domain.FileScan, path string) error {

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}

	for _, file := range files {

		if ctx.Err() == context.Canceled {
			return err
		}

		if ctx.Err() == context.DeadlineExceeded {
			return err
		}

		fmt.Println(filepath.Join(path, file.Name()))
		if file.IsDir() {
			if file.Name() == ".git" {
				continue
			}
			err = s.readFiles(ctx, ch, filepath.Join(path, file.Name()))
			if err != nil {
				return err
			}
		} else {
			content, err := os.ReadFile(filepath.Join(path, file.Name()))
			if err != nil {
				return err
			}
			data := string(content)
			ch <- domain.FileScan{
				File: filepath.Join(path, file.Name()),
				Data: data,
			}
		}
	}

	return nil
}
