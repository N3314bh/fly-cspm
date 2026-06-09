package rules

import (
	"context"
	"testing"
)

func TestPublicReachability_Evaluate(t *testing.T) {
	rule := &PublicReachability{}

	inventory := &Inventory{
		Apps: []App{
			{
				ID:         "app-db-exposed",
				Name:       "exposed-db",
				IsDatabase: true,
				PublicIPs:  []string{"1.1.1.1"},
				Machines: []Machine{
					{
						ID:    "mac-exposed",
						State: "started",
						Services: []ServiceTCP{
							{InternalPort: 5432, ExternalPort: 5432},
						},
					},
				},
			},
			{
				ID:         "app-db-mitigated",
				Name:       "mitigated-db",
				IsDatabase: true,
				PublicIPs:  []string{"2.2.2.2"}, // Has IP but no listener/services
				Machines: []Machine{
					{
						ID:       "mac-mitigated",
						State:    "started",
						Services: nil, // Zero open ports on Fly proxy edge
					},
				},
			},
		},
	}

	findings, err := rule.Evaluate(context.Background(), inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only flag the exposed database machine (mac-exposed)
	// mac-mitigated is a false positive suppressed by network reachability analysis!
	expectedFindings := 1
	if len(findings) != expectedFindings {
		t.Fatalf("expected %d findings, got %d", expectedFindings, len(findings))
	}

	if findings[0].ResourceID != "mac-exposed" {
		t.Errorf("expected finding to be for 'mac-exposed', got '%s'", findings[0].ResourceID)
	}
}
