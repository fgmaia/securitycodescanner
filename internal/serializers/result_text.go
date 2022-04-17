package serializers

import (
	"context"
	"fmt"
	"os"

	"github.com/fgmaia/securitycodescanner/internal/domain"
)

type resultText struct {
}

func NewResultText() Serializer {
	return &resultText{}
}

//[SQL injection] in file “DB.go” on line 45
func (r *resultText) Execute(ctx context.Context, result domain.ScanResult, file string) error {
	f, err := os.Create(file)

	if err != nil {
		return err
	}

	defer f.Close()

	for _, fileResult := range result.Files {
		for _, output := range fileResult.Output {

			_, err := f.WriteString(fmt.Sprintf(`[%s] in file “%s\” on line %d`,
				fileResult.ScanType.String(),
				fileResult.File, output.Line))

			if err != nil {
				return err
			}

			_, err = f.WriteString("\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}
