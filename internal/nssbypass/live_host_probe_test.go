package nssbypass

import "testing"

// A DIAGNOSTIC against the real /etc of whatever host runs the suite. It asserts
// nothing about the result (that would make the suite pass or fail by the
// developer's box, which is exactly the trap the `add` gate's seam avoids); it
// PRINTS what the detector sees, so `go test -run TestInspectThisHost -v` is a
// one-command answer to "does anonctl think this box resolves out of process, and
// what will it tell me to do about it?".
func TestInspectThisHost(t *testing.T) {
	providers, err := Inspect()
	if err != nil {
		t.Logf("inspection was incomplete: %v", err)
	}
	t.Logf("broad (add refuses): %d, narrow (disclosed): %d", len(Broad(providers)), len(Narrow(providers)))
	if len(providers) == 0 {
		t.Log("this host resolves hostnames in the calling process: nothing to refuse")
		return
	}
	t.Logf("\n%s", Explain(providers))
}
