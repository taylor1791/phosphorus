package audit

import "testing"

// A retired key's reason names who may still hold it; debt counts removals
// and re-keyed devices alike, in every format `carbon apply` writes.
func TestExposedReadsEveryReasonApplyWrites(t *testing.T) {
	for _, c := range []struct {
		reason, who string
		ok          bool
	}{
		{"removed sam", "sam", true},
		{"removed sam, lin", "sam, lin", true},
		{"removed ada/laptop, machine:deploy", "ada/laptop, machine:deploy", true},
		{"rekeyed ada/laptop", "ada/laptop's old key", true},
		{"rekeyed ada/laptop, lin/desk", "ada/laptop's old key, lin/desk's old key", true},
		{"removed sam, rekeyed ada/laptop", "sam, ada/laptop's old key", true},
		{"rotated by hand", "", false},
		{"", "", false},
		{"removed ", "", false},
	} {
		who, ok := Exposed(c.reason)
		if who != c.who || ok != c.ok {
			t.Errorf("Exposed(%q) = %q, %v; want %q, %v", c.reason, who, ok, c.who, c.ok)
		}
	}
}
