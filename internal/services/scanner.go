package services

import (
	"context"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
)

type ScannerService interface {
	Execute(ctx context.Context, path string, scanType customtypes.ScanType) (domain.ScanResult, error)
}
