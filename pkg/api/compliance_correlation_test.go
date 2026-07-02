package api

import "testing"

// TestAggregateComplianceCorrelation exercises the pure aggregation math
// against synthetic per-period inputs, independent of the DB queries that
// populate PeriodRaw in handleComplianceCorrelation.
func TestAggregateComplianceCorrelation(t *testing.T) {
	tests := []struct {
		name               string
		periods            []PeriodRaw
		controlCoveragePct float64
		want               []PeriodCorrelation
	}{
		{
			name: "mixed periods with deployments, attestations and risk scores",
			periods: []PeriodRaw{
				{
					Period:                   "2026-W01",
					Deployments:              10,
					AttestationsTotal:        20,
					AttestationsNonCompliant: 2,
					RiskScores:               []int{0, 20, 40},
				},
				{
					Period:                   "2026-W02",
					Deployments:              4,
					AttestationsTotal:        8,
					AttestationsNonCompliant: 4,
					RiskScores:               []int{100},
				},
			},
			controlCoveragePct: 0.75,
			want: []PeriodCorrelation{
				{Period: "2026-W01", Deployments: 10, ChangeFailureRate: 0.1, AvgRiskScore: 20, ControlCoveragePct: 0.75},
				{Period: "2026-W02", Deployments: 4, ChangeFailureRate: 0.5, AvgRiskScore: 100, ControlCoveragePct: 0.75},
			},
		},
		{
			name: "period with no attestations and no trails has zero rates, not NaN",
			periods: []PeriodRaw{
				{Period: "2026-W03", Deployments: 3, AttestationsTotal: 0, AttestationsNonCompliant: 0, RiskScores: nil},
			},
			controlCoveragePct: 1.0,
			want: []PeriodCorrelation{
				{Period: "2026-W03", Deployments: 3, ChangeFailureRate: 0, AvgRiskScore: 0, ControlCoveragePct: 1.0},
			},
		},
		{
			name:               "empty input yields empty output",
			periods:            nil,
			controlCoveragePct: 0.5,
			want:               []PeriodCorrelation{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aggregateComplianceCorrelation(tt.periods, tt.controlCoveragePct)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d periods, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("period %d: got %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
