package customtypes

import (
	"encoding/json"
	"errors"
)

type ScanType int

const (
	ScanTypeFull ScanType = iota
	ScanTypeCrossSiteScripting
	ScanTypeSensitiveDataExposure
	ScanTypeSqlInjection
)

func (e ScanType) String() string {
	switch e {
	case ScanTypeFull:
		return "FullScan"
	case ScanTypeCrossSiteScripting:
		return "CrossSiteScripting"
	case ScanTypeSensitiveDataExposure:
		return "SensitiveDataExposure"
	case ScanTypeSqlInjection:
		return "SqlInjection"
	}
	return "Unknown"
}

func (e *ScanType) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	value, ok := map[string]ScanType{
		"FullScan":              ScanTypeFull,
		"CrossSiteScripting":    ScanTypeCrossSiteScripting,
		"SensitiveDataExposure": ScanTypeSensitiveDataExposure,
		"SqlInjection":          ScanTypeSqlInjection,
	}[s]
	if !ok {
		return errors.New("Invalid EnumType value")
	}
	*e = value
	return nil
}

func (e *ScanType) MarshalJSON() ([]byte, error) {
	value, ok := map[ScanType]string{
		ScanTypeFull:                  "FullScan",
		ScanTypeCrossSiteScripting:    "CrossSiteScripting",
		ScanTypeSensitiveDataExposure: "SensitiveDataExposure",
		ScanTypeSqlInjection:          "SqlInjection",
	}[*e]
	if !ok {
		return nil, errors.New("Invalid EnumType value")
	}
	return json.Marshal(value)
}
