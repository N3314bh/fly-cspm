package rules

import (
	"context"
	"testing"
)

func TestPrivilegedMachines_Evaluate(t *testing.T) {
	rule := &PrivilegedMachines{}

	inventory := &Inventory{
		Apps: []App{
			{
				ID:   "app-1",
				Name: "test-app",
				Machines: []Machine{
					{
						ID:         "mach-normal",
						Name:       "normal-machine",
						Privileged: false,
					},
					{
						ID:         "mach-privileged",
						Name:       "privileged-machine",
						Privileged: true,
					},
				},
			},
		},
		Volumes: []Volume{},
	}

	findings, err := rule.Evaluate(context.Background(), inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].ResourceID != "mach-privileged" {
		t.Errorf("expected finding on mach-privileged, got '%s'", findings[0].ResourceID)
	}
}
