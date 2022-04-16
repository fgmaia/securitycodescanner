package scanners

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
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

		if strings.Contains(line, "alert(") {
			output := domain.ScanFileOutput{
				Line:    i,
				Data:    line,
				FoundAt: time.Now(),
			}
			outputs = append(outputs, output)
		}
	}

	return outputs, nil
}

func (s *crossSiteScriptScan) GetType() customtypes.ScanType {
	return customtypes.ScanTypeCrossSiteScripting
}
