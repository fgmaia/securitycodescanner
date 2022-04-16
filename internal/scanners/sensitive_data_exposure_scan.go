package scanners

import (
	"context"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
)

type sensitiveDataExposureScan struct {
}

func NewSensitiveDataExposureScan() Scan {
	return &sensitiveDataExposureScan{}
}

/*
2) Sensitive data exposure.
			Check that there are no files with following strings on a same line:
			“Checkmarx” “Hellman & Friedman” “$1.15b”

*/

func (s *sensitiveDataExposureScan) Execute(ctx context.Context, file string, data string) ([]domain.ScanFileOutput, error) {
	var outputs *[]domain.ScanFileOutput
	return outputs, nil
}

func (s *sensitiveDataExposureScan) GetType() customtypes.ScanType {
	return customtypes.ScanTypeSensitiveDataExposure
}
