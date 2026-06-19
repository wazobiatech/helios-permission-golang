package helios_permissions

import "time"

// secondsToDuration converts a non-negative integer seconds value to
// a time.Duration. Returns 0 for negative inputs (matches the behavior
// of time.Duration arithmetic underflow protection).
func secondsToDuration(s int) time.Duration {
	if s <= 0 {
		return 0
	}
	return time.Duration(s) * time.Second
}
