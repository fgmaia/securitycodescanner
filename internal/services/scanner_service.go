package services

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/internal/filesearch"
	"github.com/fgmaia/securitycodescanner/internal/scanners"
	"github.com/fgmaia/securitycodescanner/pkg/realtime"
	"golang.org/x/sync/errgroup"
)

type scannerService struct {
	maxParallel int
	fileSearch  filesearch.FileSearch
	scanType    customtypes.ScanType
	scans       []scanners.Scan
	mu          sync.Mutex
}

func NewScannerService(fileSearch filesearch.FileSearch,
	maxParallel int,
	scanType customtypes.ScanType,
	scans ...scanners.Scan) ScannerService {

	return &scannerService{
		fileSearch:  fileSearch,
		maxParallel: maxParallel,
		scanType:    scanType,
		scans:       scans,
	}
}

func (s *scannerService) Execute(ctx context.Context, path string) (domain.ScanResult, error) {
	fmt.Printf("Start Scanning")

	scanResult := domain.ScanResult{
		StartAt: realtime.Now(),
		Path:    path,
	}

	var sema = make(chan struct{}, s.maxParallel)
	errorgroup, ctx := errgroup.WithContext(ctx)

	chFiles := s.fileSearch.Execute(ctx, path)
	total := 0
	for fileScan := range chFiles {
		total++
		fileScan := fileScan
		if ctx.Err() == context.Canceled {
			return scanResult, errors.New("canceled")
		}

		if ctx.Err() == context.DeadlineExceeded {
			return scanResult, errors.New("deadline is exceeded")
		}

		if fileScan.Error != nil {
			return scanResult, fileScan.Error
		}

		f := func() error {
			sema <- struct{}{}        // acquire token
			defer func() { <-sema }() //release token

			scannedFiles, err := s.processFile(ctx, fileScan.File, fileScan.Data)
			if err != nil {
				return err
			}

			if len(scannedFiles) > 0 {
				t := 0
				for _, s := range scannedFiles {
					t += s.VulnerabilitiesFound
				}
				s.mu.Lock()
				scanResult.Files = append(scanResult.Files, scannedFiles...)
				scanResult.VulnerabilitiesFound += t
				s.mu.Unlock()
			}
			return nil
		}
		errorgroup.Go(f)

	}

	err := errorgroup.Wait()
	if err != nil {
		return scanResult, err
	}

	scanResult.EndAt = realtime.Now()
	scanResult.TotalScannedFiles = total

	return scanResult, nil
}

func (s *scannerService) processFile(ctx context.Context, file string, data string) ([]domain.ScanFile, error) {
	var scanFiles []domain.ScanFile

	for _, scan := range s.scans {
		if ctx.Err() == context.Canceled {
			return scanFiles, errors.New("canceled")
		}

		if ctx.Err() == context.DeadlineExceeded {
			return scanFiles, errors.New("deadline is exceeded")
		}
		scans, err := s.processData(ctx, file, data, scan)
		if err != nil {
			return scanFiles, err
		}
		if scans != nil {
			scanFiles = append(scanFiles, *scans)
		}
	}

	return scanFiles, nil
}

func (s *scannerService) processData(ctx context.Context, file string, data string, scan scanners.Scan) (*domain.ScanFile, error) {
	scanFile := domain.ScanFile{
		File:     file,
		ScanType: scan.GetType(),
		StartAt:  realtime.Now(),
	}

	scanOutputs, err := scan.Execute(ctx, file, data)
	scanFile.EndAt = realtime.Now()
	if err != nil {
		return nil, err
	}

	if len(scanOutputs) == 0 {
		return nil, nil
	}

	scanFile.Output = scanOutputs
	scanFile.VulnerabilitiesFound = len(scanOutputs)

	return &scanFile, nil
}
