package filesearch_test

import (
	"context"
	"testing"

	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/internal/filesearch"
	"github.com/stretchr/testify/require"
)

func TestFileSearch(t *testing.T) {
	t.Parallel()

	fsearch := filesearch.NewFileSearch(1)

	t.Run("when success found", func(t *testing.T) {
		t.Parallel()
		ch := fsearch.Execute(context.Background(), "../../mocks/filesearch")
		var fScan domain.FileScan
		for fileScan := range ch {
			fScan = fileScan
		}
		require.NoError(t, fScan.Error)
		require.NotEmpty(t, fScan.Data)
	})
}
