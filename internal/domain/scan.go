package domain

import (
	"time"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
)

type ScanResult struct {
	Path                 string               `json:"path"`
	ScanType             customtypes.ScanType `json:"scan_type"`
	StartAt              time.Time            `json:"start_at"`
	EndAt                time.Time            `json:"end_at"`
	Files                []ScanFile           `json:"files,omitempty"`
	TotalScannedFiles    int                  `json:"total_scanned_files"`
	VulnerabilitiesFound int                  `json:"vulnerabilities_found"`
}

type ScanFile struct {
	File                 string               `json:"file_name"`
	ScanType             customtypes.ScanType `json:"scan_type"`
	Output               []ScanFileOutput     `json:"vulnerabilities,omitempty"`
	VulnerabilitiesFound int                  `json:"vulnerabilities_found"`
	StartAt              time.Time            `json:"start_at"`
	EndAt                time.Time            `json:"end_at"`
}

type ScanFileOutput struct {
	Line    int       `json:"line_number"`
	Data    string    `json:"data"`
	FoundAt time.Time `json:"found_at"`
}

type FileScan struct {
	File  string
	Data  string
	Error error
}
