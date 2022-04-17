package scanners

import (
	"context"
	"errors"
	"strings"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/pkg/realtime"
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
	var outputs []domain.ScanFileOutput

	lines := strings.Split(data, "\n")
	for i, line := range lines {
		if ctx.Err() == context.Canceled {
			return outputs, errors.New("canceled")
		}

		if ctx.Err() == context.DeadlineExceeded {
			return outputs, errors.New("deadline is exceeded")
		}

		lineLower := strings.ToLower(line)

		if strings.Contains(lineLower, "checkmarx") &&
			strings.Contains(lineLower, "hellman & friedman") &&
			strings.Contains(lineLower, "$1.15b") {

			output := domain.ScanFileOutput{
				Line:    i + 1,
				Data:    strings.Trim(line, " "),
				FoundAt: realtime.Now(),
			}
			outputs = append(outputs, output)
		}
	}

	return outputs, nil
}

func (s *sensitiveDataExposureScan) GetType() customtypes.ScanType {
	return customtypes.ScanTypeSensitiveDataExposure
}
