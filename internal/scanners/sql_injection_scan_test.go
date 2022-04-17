package scanners_test

import (
	"context"
	"testing"

	"github.com/fgmaia/securitycodescanner/internal/scanners"
	"github.com/stretchr/testify/require"
)

func TestSqlInjection(t *testing.T) {
	t.Parallel()

	validMatchData := `3) SQL injection
		Check that there are no files
		with statements starting with quotes, containing SELECT, WHERE, %s and ending with quotes
		e.g. "…. SELECT …. WHERE …. %s …. "`

	invalidMatchData := `3) SQL injection
		Check that there are no files
		with statements starting with quotes, containing SELECT, WHERE, %s and ending with quotes
		e.g. …. SELEC …. WHERE …. %s …. "`

	scan := scanners.NewSqlInjection()

	t.Run("when not found", func(t *testing.T) {
		output, err := scan.Execute(context.Background(), "test.sql", invalidMatchData)
		require.NoError(t, err)
		require.Equal(t, len(output), 0)
	})

	t.Run("when success found", func(t *testing.T) {
		output, err := scan.Execute(context.Background(), "test.sql", validMatchData)
		require.NoError(t, err)
		require.Equal(t, len(output), 1)
	})

}
