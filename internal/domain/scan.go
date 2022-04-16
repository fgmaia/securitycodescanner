package domain

import (
	"time"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
)

type ScanResult struct {
	Path                 string
	ScanType             customtypes.ScanType
	StartAt              time.Time
	EndAt                time.Time
	Files                []ScanFile
	VulnerabilitiesFound int
}

type ScanFile struct {
	File                 string
	ScanType             customtypes.ScanType
	Output               []ScanFileOutput
	VulnerabilitiesFound int
	StartAt              time.Time
	EndAt                time.Time
}

type ScanFileOutput struct {
	Line    int
	Data    string
	FoundAt time.Time
}
