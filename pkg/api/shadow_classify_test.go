package api

import (
	"strings"
	"testing"
)

// The whole point of #432 is that these two read differently. If they ever
// converge again, the operator is back to approving digests without looking.
func TestShadowMessageDistinguishesUpgradeFromUnknown(t *testing.T) {
	const svc, digest = "reporter", "0a80d1f17932146c960925abca093e15f27cdec85305199320812cace6ad67a7"

	unknown := shadowMessage(svc, digest, false)
	upgrade := shadowMessage(svc, digest, true)

	if unknown == upgrade {
		t.Fatal("an unapproved upgrade and a wholly unknown image must not produce " +
			"the same verdict line — that identity is the bug")
	}
	for _, m := range []string{unknown, upgrade} {
		if !strings.Contains(m, svc) || !strings.Contains(m, digest) {
			t.Errorf("message must still name the service and digest: %q", m)
		}
	}
	if !strings.Contains(upgrade, "previously approved") {
		t.Errorf("the upgrade case must say the image was approved before: %q", upgrade)
	}
	if strings.Contains(unknown, "previously approved") {
		t.Errorf("an unknown image must NOT claim prior approval: %q", unknown)
	}
	// The operator's next action should be obvious from the line itself.
	if !strings.Contains(upgrade, "approve the new digest") {
		t.Errorf("the upgrade case should name the remedy: %q", upgrade)
	}
}

// An empty service name carries no identity to correlate on, so it cannot be
// claimed as a known upgrade. Guards the nil-DB path too: the helper must not
// query when there is nothing to query for.
func TestServiceHasPriorApprovalRejectsEmptyServiceName(t *testing.T) {
	if serviceHasPriorApproval(nil, nil, [16]byte{}, "") {
		t.Error("an unnamed service must never be treated as a known upgrade")
	}
}
