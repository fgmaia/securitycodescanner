package serializers

import (
	"context"
	"encoding/json"
	"io/ioutil"

	"github.com/fgmaia/securitycodescanner/internal/domain"
)

type resultJson struct {
}

func NewResultJson() Serializer {
	return &resultJson{}
}

func (r *resultJson) Execute(ctx context.Context, result domain.ScanResult, file string) error {
	data, err := json.MarshalIndent(&result, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(file, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
