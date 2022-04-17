package serializers

import (
	"context"

	"github.com/fgmaia/securitycodescanner/internal/domain"
)

type Serializer interface {
	Execute(ctx context.Context, result domain.ScanResult, file string) error
}
