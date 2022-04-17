package scanners_test

import (
	"context"
	"testing"

	"github.com/fgmaia/securitycodescanner/internal/scanners"
	"github.com/stretchr/testify/require"
)

func TestCrossSiteScripting(t *testing.T) {
	t.Parallel()

	validMatchData := `1) Cross site scripting
	Check that there are no html or JavaScript files with following statement:
	Alert()`

	invalidMatchData := `1) Cross site scripting
	Check that there are no html or JavaScript files with following statement:
	lert()`

	scan := scanners.NewCrossSiteScriptScan()

	t.Run("when not found", func(t *testing.T) {
		output, err := scan.Execute(context.Background(), "test.html", invalidMatchData)
		require.NoError(t, err)
		require.Equal(t, len(output), 0)
	})

	t.Run("when success found", func(t *testing.T) {
		output, err := scan.Execute(context.Background(), "test.html", validMatchData)
		require.NoError(t, err)
		require.Equal(t, len(output), 1)
	})

}
