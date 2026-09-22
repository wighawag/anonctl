package forcing

import "time"

// SetShimStartTimeoutForTest shortens the active-wait so the unhappy path does not
// cost the suite ten seconds. Test-only seam.
func SetShimStartTimeoutForTest(d time.Duration) { shimStartTimeout = d }
