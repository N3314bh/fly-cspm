package rules

import (
	"context"
	"fmt"
)

func init() {
	Register(&UnencryptedVolumes{})
}

// UnencryptedVolumes checks for storage volumes that are not encrypted.
type UnencryptedVolumes struct{}

func (r *UnencryptedVolumes) ID() string {
	return "FLY-VOL-002"
}

func (r *UnencryptedVolumes) Name() string {
	return "Unencrypted Storage Volumes"
}

func (r *UnencryptedVolumes) Description() string {
	return "Identifies volumes that are not encrypted. Encrypted volumes prevent unauthorized access to data at rest."
}

func (r *UnencryptedVolumes) Severity() Severity {
	return SeverityHigh
}

// Evaluate scans the inventory volumes and flags any that are unencrypted.
func (r *UnencryptedVolumes) Evaluate(ctx context.Context, inventory *Inventory) ([]Finding, error) {
	var findings []Finding

	for _, vol := range inventory.Volumes {
		if !vol.Encrypted {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				ResourceID:   vol.ID,
				ResourceType: "Volume",
				Severity:     r.Severity(),
				Message:      fmt.Sprintf("Volume %q (%s) is unencrypted. Enable volume encryption to secure data at rest.", vol.Name, vol.ID),
			})
		}
	}

	return findings, nil
}
