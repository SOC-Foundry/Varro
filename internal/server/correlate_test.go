package server

import "testing"

func TestCorrelatorThresholdAndRefire(t *testing.T) {
	c := newCorrelator()
	ind := "ip:203.0.113.5"

	// First two distinct endpoints: below threshold, no fire.
	if n, fire := c.observe(ind, "ep1"); fire || n != 1 {
		t.Fatalf("ep1: n=%d fire=%v", n, fire)
	}
	if n, fire := c.observe(ind, "ep2"); fire || n != 2 {
		t.Fatalf("ep2: n=%d fire=%v", n, fire)
	}
	// Third distinct endpoint crosses the threshold: fire.
	if n, fire := c.observe(ind, "ep3"); !fire || n != 3 {
		t.Fatalf("ep3 should fire: n=%d fire=%v", n, fire)
	}
	// A 4th endpoint within the re-fire window must NOT fire again.
	if _, fire := c.observe(ind, "ep4"); fire {
		t.Fatal("should not re-fire within the window")
	}
	// A repeat of an already-counted endpoint doesn't re-fire either.
	if _, fire := c.observe(ind, "ep1"); fire {
		t.Fatal("repeat endpoint should not re-fire")
	}
	// A different indicator is tracked independently.
	if _, fire := c.observe("domain:evil.example", "ep1"); fire {
		t.Fatal("new indicator with one endpoint should not fire")
	}
}
