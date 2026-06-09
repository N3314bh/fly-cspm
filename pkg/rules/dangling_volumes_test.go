package rules

import (
	"context"
	"testing"
)

func TestDanglingVolumes_Evaluate(t *testing.T) {
	rule := &DanglingVolumes{}

	inventory := &Inventory{
		Apps: []App{
			{
				ID: "app-active",
				Machines: []Machine{
					{ID: "mac-1", State: "started"},
				},
			},
			{
				ID: "app-idle",
				Machines: []Machine{
					{ID: "mac-2", State: "stopped"},
				},
			},
		},
		Volumes: []Volume{
			{
				ID:    "vol-attached",
				Name:  "active-data",
				AppID: "app-active",
				State: "attached",
			},
			{
				ID:    "vol-dangling-state",
				Name:  "dangling-state-data",
				AppID: "app-active",
				State: "detached",
			},
			{
				ID:    "vol-dangling-app",
				Name:  "orphaned-app-data",
				AppID: "app-idle",
				State: "attached", // App has no running machines, so this is functionally dangling/unmonitored
			},
		},
	}

	findings, err := rule.Evaluate(context.Background(), inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should flag vol-dangling-state and vol-dangling-app
	expectedFindings := 2
	if len(findings) != expectedFindings {
		t.Errorf("expected %d findings, got %d", expectedFindings, len(findings))
	}
}
