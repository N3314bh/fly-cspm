package rules

import (
	"context"
	"fmt"
)

func init() {
	Register(&DanglingVolumes{})
}

// DanglingVolumes checks for storage volumes that are not attached to any active machine.
type DanglingVolumes struct{}

func (r *DanglingVolumes) ID() string {
	return "FLY-VOL-001"
}

func (r *DanglingVolumes) Name() string {
	return "Orphaned Volumes"
}

func (r *DanglingVolumes) Description() string {
	return "Identifies volumes that are unattached. These volumes may contain stale credentials, PII, or database state, representing an unnecessary data-at-rest exposure risk and ongoing storage costs."
}

func (r *DanglingVolumes) Severity() Severity {
	return SeverityMedium
}

// Evaluate identifies detached volumes by mapping active machines.
func (r *DanglingVolumes) Evaluate(ctx context.Context, inventory *Inventory) ([]Finding, error) {
	var findings []Finding

	// Idiomatic Go: Use a map as a set to track which apps have active machines running.
	// This optimizes lookup complexity from O(N*M) to O(N+M).
	activeApps := make(map[string]bool)
	for _, app := range inventory.Apps {
		for _, machine := range app.Machines {
			if machine.State == "started" || machine.State == "starting" {
				activeApps[app.ID] = true
			}
		}
	}

	for _, vol := range inventory.Volumes {
		// If a volume is in a detached state or belongs to an app with no active machines running, flag it.
		hasActiveCompute := activeApps[vol.AppID]
		if vol.State == "detached" || !hasActiveCompute {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				ResourceID:   vol.ID,
				ResourceType: "Volume",
				Severity:     r.Severity(),
				Message:      fmt.Sprintf("Volume %q (%s) is dangling. App %q has no active compute machines to safely consume this storage.", vol.Name, vol.ID, vol.AppID),
			})
		}
	}

	return findings, nil
}
