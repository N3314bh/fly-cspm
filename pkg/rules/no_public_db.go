package rules

import (
	"context"
	"fmt"
)

func init() {
	Register(&NoPublicDB{})
}

// NoPublicDB implements the Rule interface to check for database apps exposed publicly.
type NoPublicDB struct{}

// ID returns the unique identifier for the rule.
func (r *NoPublicDB) ID() string {
	return "FLY-NET-001"
}

// Name returns a human-readable name for the rule.
func (r *NoPublicDB) Name() string {
	return "No Public Databases"
}

// Description returns a detailed description of the security check.
func (r *NoPublicDB) Description() string {
	return "Database applications must not have public IPv4 or IPv6 addresses. They should only be accessible via WireGuard or the Fly.io private 6PN network."
}

// Severity returns the risk level of violating this rule.
func (r *NoPublicDB) Severity() Severity {
	return SeverityCritical
}

// Evaluate scans the inventory and flags database applications with public IP addresses.
func (r *NoPublicDB) Evaluate(ctx context.Context, inventory *Inventory) ([]Finding, error) {
	var findings []Finding

	for _, app := range inventory.Apps {
		if app.IsDatabase && len(app.PublicIPs) > 0 {
			// Check if any machine in this app has active services (which would be covered by FLY-NET-002)
			hasActiveServices := false
			for _, m := range app.Machines {
				if len(m.Services) > 0 && (m.State == "started" || m.State == "starting") {
					hasActiveServices = true
					break
				}
			}

			if !hasActiveServices {
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					RuleName:     r.Name(),
					ResourceID:   app.ID,
					ResourceType: "App",
					Severity:     r.Severity(),
					Message:      fmt.Sprintf("Database application %q has public IP addresses: %v", app.Name, app.PublicIPs),
				})
			}
		}
	}

	return findings, nil
}
