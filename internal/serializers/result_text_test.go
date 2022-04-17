package serializers_test

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/internal/serializers"
	"github.com/fgmaia/securitycodescanner/pkg/realtime"
	"github.com/stretchr/testify/require"
)

func TestResultText(t *testing.T) {
	t.Parallel()

	resultTxt := serializers.NewResultText()

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

	fileName := "result.txt"

	t.Run("when success", func(t *testing.T) {
		t.Parallel()

		err := resultTxt.Execute(context.Background(), result, fileName)
		require.NoError(t, err)

		txtData, err := ioutil.ReadFile(fileName)
		require.NoError(t, err)

		require.NotEmpty(t, result.Path, txtData)

		os.Remove(fileName)
	})
}
