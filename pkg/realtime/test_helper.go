package realtime

import "time"

func MockTestsTime(customtime time.Time) {
	Now = func() time.Time { return customtime }
}
