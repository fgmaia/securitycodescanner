package scanners

import (
	"context"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
)

type Scan interface {
	Execute(ctx context.Context, file string, data string) ([]domain.ScanFileOutput, error)
	GetType() customtypes.ScanType
}
