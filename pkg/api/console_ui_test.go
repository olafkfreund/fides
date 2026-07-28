package api

import "testing"

func TestCompliancePct(t *testing.T) {
	cases := []struct {
		compliant, total, want int
	}{
		{0, 0, 0},     // no checks
		{99, 100, 99}, // the screenshot case
		{100, 100, 100},
		{1, 3, 33}, // 33.3 -> 33
		{2, 3, 67}, // 66.6 -> 67 (half-up)
		{5, 5, 100},
		{0, 10, 0},
	}
	for _, c := range cases {
		if got := compliancePct(c.compliant, c.total); got != c.want {
			t.Errorf("compliancePct(%d,%d) = %d, want %d", c.compliant, c.total, got, c.want)
		}
	}
}
