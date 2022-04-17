package realtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNow(t *testing.T) {
	require.Equal(t, Now(), time.Now())
}

func TestMockTestsTime(t *testing.T) {
	currentTime := time.Now()
	MockTestsTime(currentTime)

	require.Equal(t, Now(), currentTime)
}
