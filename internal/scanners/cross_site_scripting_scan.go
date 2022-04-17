package scanners

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/pkg/realtime"
)

/*
	1) Cross site scripting
			Check that there are no html or JavaScript files with following statement:
			Alert()
*/

type crossSiteScriptScan struct {
}

func NewCrossSiteScriptScan() Scan {
	return &crossSiteScriptScan{}
}

func (s *crossSiteScriptScan) Execute(ctx context.Context, file string, data string) ([]domain.ScanFileOutput, error) {
	var outputs []domain.ScanFileOutput

	fileExtension := filepath.Ext(file)

	if fileExtension != ".html" && fileExtension != ".htm" && fileExtension != ".js" && fileExtension == ".javascript" {
		return outputs, nil
	}

	lines := strings.Split(data, "\n")
	for i, line := range lines {
		if ctx.Err() == context.Canceled {
			return outputs, errors.New("canceled")
		}

		if ctx.Err() == context.DeadlineExceeded {
			return outputs, errors.New("deadline is exceeded")
		}

		lineLower := strings.ToLower(line)

		if strings.Contains(lineLower, "alert(") {
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

func (s *crossSiteScriptScan) GetType() customtypes.ScanType {
	return customtypes.ScanTypeCrossSiteScripting
}
