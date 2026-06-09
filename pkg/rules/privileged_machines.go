package rules

import (
	"context"
	"fmt"
)

func init() {
	Register(&PrivilegedMachines{})
}

// PrivilegedMachines checks for machines running with privileged mode.
type PrivilegedMachines struct{}

func (r *PrivilegedMachines) ID() string {
	return "FLY-MAC-001"
}

func (r *PrivilegedMachines) Name() string {
	return "Privileged Machine Container Execution"
}

func (r *PrivilegedMachines) Description() string {
	return "Identifies machines running with privileged container flags. Privileged machines bypass typical container isolation controls and can expose the host to root privilege escape attacks."
}

func (r *PrivilegedMachines) Severity() Severity {
	return SeverityHigh
}

// Evaluate scans the inventory machines and flags any that are privileged.
func (r *PrivilegedMachines) Evaluate(ctx context.Context, inventory *Inventory) ([]Finding, error) {
	var findings []Finding

	for _, app := range inventory.Apps {
		for _, mach := range app.Machines {
			if mach.Privileged {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					RuleName:     r.Name(),
					ResourceID:   mach.ID,
					ResourceType: "Machine",
					Severity:     r.Severity(),
					Message:      fmt.Sprintf("Machine %q (%s) in app %q is running with privileged permission.", mach.Name, mach.ID, app.Name),
				})
			}
		}
	}

	return findings, nil
}
