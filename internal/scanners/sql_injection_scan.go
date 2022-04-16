package scanners

import (
	"context"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
)

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
			There are 2 supported output formats and adding the additional formats should be simple.

*/

func (s *sqlInjectionScan) Execute(ctx context.Context, file string, data string) ([]domain.ScanFileOutput, error) {
	var outputs []domain.ScanFileOutput
	return outputs, nil
}
func (s *sqlInjectionScan) GetType() customtypes.ScanType {
	return customtypes.ScanTypeSensitiveDataExposure
}
