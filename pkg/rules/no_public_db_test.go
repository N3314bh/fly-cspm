package rules

import (
	"context"
	"testing"
)

func TestNoPublicDB_Evaluate(t *testing.T) {
	rule := &NoPublicDB{}

	tests := []struct {
		name      string
		inventory *Inventory
		wantCount int
	}{
		{
			name: "Secure database app (no public IPs)",
			inventory: &Inventory{
				Apps: []App{
					{
						ID:         "app-1",
						Name:       "prod-postgres",
						IsDatabase: true,
						PublicIPs:  []string{},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "Vulnerable database app (has public IP)",
			inventory: &Inventory{
				Apps: []App{
					{
						ID:         "app-2",
						Name:       "dev-redis",
						IsDatabase: true,
						PublicIPs:  []string{"1.2.3.4"},
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "Public non-database app (acceptable)",
			inventory: &Inventory{
				Apps: []App{
					{
						ID:         "app-3",
						Name:       "marketing-frontend",
						IsDatabase: false,
						PublicIPs:  []string{"1.2.3.4"},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "Vulnerable database app with active machine services (should be bypassed and left to reachability rule)",
			inventory: &Inventory{
				Apps: []App{
					{
						ID:         "app-4",
						Name:       "prod-db-exposed",
						IsDatabase: true,
						PublicIPs:  []string{"1.2.3.4"},
						Machines: []Machine{
							{
								ID:    "mach-1",
								State: "started",
								Services: []ServiceTCP{
									{InternalPort: 5432, ExternalPort: 5432},
								},
							},
						},
					},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := rule.Evaluate(context.Background(), tt.inventory)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(findings) != tt.wantCount {
				t.Errorf("NoPublicDB.Evaluate() = %d findings, want %d", len(findings), tt.wantCount)
			}

			if len(findings) > 0 {
				finding := findings[0]
				if finding.RuleID != rule.ID() {
					t.Errorf("expected rule ID %q, got %q", rule.ID(), finding.RuleID)
				}
				if finding.Severity != SeverityCritical {
					t.Errorf("expected severity CRITICAL, got %s", finding.Severity)
				}
			}
		})
	}
}
