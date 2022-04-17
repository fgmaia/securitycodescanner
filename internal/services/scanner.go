package services

import (
	"context"

	"github.com/fgmaia/securitycodescanner/internal/domain"
)

type ScannerService interface {
	Execute(ctx context.Context, path string) (domain.ScanResult, error)
}
