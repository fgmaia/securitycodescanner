package realtime

import "time"

var Now = func() time.Time {
	return time.Now()
}
