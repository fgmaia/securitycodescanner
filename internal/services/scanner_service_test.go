package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/domain"
	"github.com/fgmaia/securitycodescanner/internal/scanners"
	"github.com/fgmaia/securitycodescanner/internal/services"
	"github.com/fgmaia/securitycodescanner/mocks"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestExecute(t *testing.T) {
	t.Parallel()

	t.Run("when fileSearch returns an error", func(t *testing.T) {
		t.Parallel()

		fileScan1 := domain.FileScan{
			File:  "test1.js",
			Data:  "alert()",
			Error: nil,
		}

		fileScanError := domain.FileScan{
			File:  "test2.html",
			Data:  "",
			Error: errors.New("error reading file"),
		}

		ctx := context.Background()
		_, ctxCancel := errgroup.WithContext(ctx)

		fileSearchMock := &mocks.FileSearch{}
		ch := make(chan domain.FileScan, 2)

		chRec := make(<-chan domain.FileScan, 2)
		chRec = ch
		fileSearchMock.On("Execute", ctxCancel, "/.").Return(chRec)

		ch <- fileScan1
		ch <- fileScanError
		close(ch)

		scan := services.NewScannerService(fileSearchMock,
			1,
			customtypes.ScanTypeCrossSiteScripting,
			scanners.NewCrossSiteScriptScan())

		result, err := scan.Execute(ctx, "/.")
		require.Error(t, err)
		require.Equal(t, result.TotalScannedFiles, 0)
	})

	t.Run("when success", func(t *testing.T) {
		t.Parallel()

		fileScan1 := domain.FileScan{
			File:  "test1.js",
			Data:  "alert()",
			Error: nil,
		}

		fileScan2 := domain.FileScan{
			File:  "test2.html",
			Data:  "test test alert() test",
			Error: nil,
		}

		ctx := context.Background()
		_, ctxCancel := errgroup.WithContext(ctx)

		fileSearchMock := &mocks.FileSearch{}
		ch := make(chan domain.FileScan, 2)

		chRec := make(<-chan domain.FileScan, 2)
		chRec = ch
		fileSearchMock.On("Execute", ctxCancel, "/.").Return(chRec)

		ch <- fileScan1
		ch <- fileScan2
		close(ch)

		scan := services.NewScannerService(fileSearchMock,
			1,
			customtypes.ScanTypeCrossSiteScripting,
			scanners.NewCrossSiteScriptScan())

		result, err := scan.Execute(ctx, "/.")
		require.NoError(t, err)
		require.Equal(t, result.TotalScannedFiles, 2)
		require.Equal(t, result.VulnerabilitiesFound, 2)
	})
}
