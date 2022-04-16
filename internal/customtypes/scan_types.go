package customtypes

type ScanType int

const (
	ScanTypeFull ScanType = iota
	ScanTypeCrossSiteScripting
	ScanTypeSensitiveDataExposure
	ScanTypeCrossSqlInjection
)
