package serializers_test

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/internal/serializers"
	"github.com/fgmaia/securitycodescanner/pkg/realtime"
	"github.com/stretchr/testify/require"
)

func TestResultJson(t *testing.T) {
	t.Parallel()

	resultJson := serializers.NewResultJson()

	result := domain.ScanResult{
		Path:     "./",
		ScanType: customtypes.ScanTypeCrossSiteScripting,
		StartAt:  realtime.Now(),
		EndAt:    realtime.Now(),
		Files: []domain.ScanFile{
			{
				File:     "./test.go",
				ScanType: customtypes.ScanTypeCrossSiteScripting,
				Output: []domain.ScanFileOutput{
					{
						Line:    1,
						Data:    "alert",
						FoundAt: realtime.Now(),
					},
				},
				VulnerabilitiesFound: 1,
				StartAt:              realtime.Now(),
				EndAt:                realtime.Now(),
			},
		},
		TotalScannedFiles:    1,
		VulnerabilitiesFound: 1,
	}

	fileName := "result.json"

	t.Run("when success", func(t *testing.T) {
		t.Parallel()

		err := resultJson.Execute(context.Background(), result, fileName)
		require.NoError(t, err)

		jsonData, err := ioutil.ReadFile(fileName)
		require.NoError(t, err)

		var result1 domain.ScanResult
		err = json.Unmarshal(jsonData, &result1)
		require.NoError(t, err)

		require.Equal(t, result.Path, result1.Path)

		os.Remove(fileName)
	})
}
