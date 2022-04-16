package services

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/internal/scanners"
)

type scannerService struct {
}

func NewScannerService() ScannerService {
	return &scannerService{}
}

func (s *scannerService) Execute(ctx context.Context, path string, scanType customtypes.ScanType) (domain.ScanResult, error) {
	fmt.Printf("Start Scanning")

	scans := make([]scanners.Scan, 0, 1)

	switch scanType {
	case customtypes.ScanTypeFull:
		scans = append(scans, scanners.NewCrossSiteScriptScan())
		scans = append(scans, scanners.NewSensitiveDataExposureScan())
		scans = append(scans, scanners.NewSqlInjection())

	case customtypes.ScanTypeCrossSiteScripting:
		scans = append(scans, scanners.NewCrossSiteScriptScan())

	case customtypes.ScanTypeCrossSqlInjection:
		scans = append(scans, scanners.NewSqlInjection())

	case customtypes.ScanTypeSensitiveDataExposure:
		scans = append(scans, scanners.NewSensitiveDataExposureScan())
	}

	scanResult := &domain.ScanResult{}
	err := s.processFiles(ctx, scanResult, path, scans...)
	if err != nil {
		return *scanResult, err
	}

	return *scanResult, nil
}

func (s *scannerService) processFiles(ctx context.Context, scanResult *domain.ScanResult, path string, scans ...scanners.Scan) error {

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}

	var scanFiles []domain.ScanFile
	for _, file := range files {

		if ctx.Err() == context.Canceled {
			return errors.New("canceled")
		}

		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("deadline is exceeded")
		}

		if !file.IsDir() {
			if err := s.processFiles(ctx, scanResult, filepath.Join(path, file.Name()), scans...); err != nil {
				return err
			}
		} else {
			scanFiles, err = s.processFile(ctx, filepath.Join(path, file.Name()), scans...)
			if err != nil {
				return err
			}
			scanResult.Files = append(scanResult.Files, scanFiles...)
		}
	}

	return nil
}

func (s *scannerService) processFile(ctx context.Context, file string, scans ...scanners.Scan) ([]domain.ScanFile, error) {
	var scanFiles []domain.ScanFile
	//

	content, err := os.ReadFile("file.txt")
	if err != nil {
		return scanFiles, err
	}
	data := string(content)

	for _, scan := range scans {
		if ctx.Err() == context.Canceled {
			return scanFiles, errors.New("canceled")
		}

		if ctx.Err() == context.DeadlineExceeded {
			return scanFiles, errors.New("deadline is exceeded")
		}
		s.processData(ctx, file, data, scan)
	}

	return scanFiles, nil
}

func (s *scannerService) processData(ctx context.Context, file string, data string, scan scanners.Scan) (domain.ScanFile, error) {
	scanFile := domain.ScanFile{
		File:     file,
		ScanType: scan.GetType(),
		StartAt:  time.Now(),
	}

	scanOutputs, err := scan.Execute(ctx, file, data)
	scanFile.EndAt = time.Now()
	if err != nil {
		return scanFile, err
	}
	scanFile.Output = scanOutputs
	scanFile.VulnerabilitiesFound = len(scanOutputs)

	return scanFile, nil
}
