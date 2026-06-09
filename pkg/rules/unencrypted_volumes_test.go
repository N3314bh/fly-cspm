package rules

import (
	"context"
	"testing"
)

func TestUnencryptedVolumes_Evaluate(t *testing.T) {
	rule := &UnencryptedVolumes{}

	inventory := &Inventory{
		Apps: []App{},
		Volumes: []Volume{
			{
				ID:        "vol-1",
				Name:      "encrypted-vol",
				Encrypted: true,
			},
			{
				ID:        "vol-2",
				Name:      "unencrypted-vol",
				Encrypted: false,
			},
		},
	}

	findings, err := rule.Evaluate(context.Background(), inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].ResourceID != "vol-2" {
		t.Errorf("expected finding on vol-2, got '%s'", findings[0].ResourceID)
	}
}
