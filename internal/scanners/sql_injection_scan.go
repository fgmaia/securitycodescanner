package scanners

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/pkg/realtime"
)

var regexSqlInjection = regexp.MustCompile(`".*(select).+(where).+(%s).*"`)

type sqlInjectionScan struct {
}

func NewSqlInjection() Scan {
	return &sqlInjectionScan{}
}

/*
	3) SQL injection
			Check that there are no files
			with statements starting with quotes, containing SELECT, WHERE, %s and ending with quotes
			e.g. "…. SELECT …. WHERE …. %s …. "
*/

func (s *sqlInjectionScan) Execute(ctx context.Context, file string, data string) ([]domain.ScanFileOutput, error) {
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

		if regexSqlInjection.MatchString(lineLower) {

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
func (s *sqlInjectionScan) GetType() customtypes.ScanType {
	return customtypes.ScanTypeSensitiveDataExposure
}
