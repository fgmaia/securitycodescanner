package scanners_test

import (
	"context"
	"testing"

	"github.com/fgmaia/securitycodescanner/internal/scanners"
	"github.com/stretchr/testify/require"
)

func TestSensitiveDataExposure(t *testing.T) {
	t.Parallel()

	validMatchData := `2) Sensitive data exposure.
	Check that there are no files with following strings on a same line:
	“Checkmarx” “Hellman & Friedman” “$1.15b”`

	invalidMatchData := `2) Sensitive data exposure.
	Check that there are no files with following strings on a same line:
	“Checkmar” “Hellman & Friedma” “$1.15b”`

	scan := scanners.NewSensitiveDataExposureScan()

	t.Run("when not found", func(t *testing.T) {
		output, err := scan.Execute(context.Background(), "test", invalidMatchData)
		require.NoError(t, err)
		require.Equal(t, len(output), 0)
	})

	t.Run("when success found", func(t *testing.T) {
		output, err := scan.Execute(context.Background(), "test", validMatchData)
		require.NoError(t, err)
		require.Equal(t, len(output), 1)
	})

}
