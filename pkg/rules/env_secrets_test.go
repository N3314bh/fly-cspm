package rules

import (
	"context"
	"strings"
	"testing"
)

func TestEnvSecrets_Evaluate(t *testing.T) {
	rule := &EnvSecrets{}

	inventory := &Inventory{
		Apps: []App{
			{
				ID:   "app-vuln",
				Name: "vulnerable-app",
				EnvVariables: map[string]string{
					"DATABASE_URL":      "postgres://user:super-secret-password@localhost:5432/db",
					"STRIPE_API_KEY":    "sk_live_abcdef123456",
					"DEFAULT_REGION":    "ams",               // Safe key
					"APP_DEBUG":         "false",             // Safe key/value
					"SLACK_AUTH_TOKEN":  "change-me",         // Key matches secret, but value is placeholder
					"AWS_SECRET_KEY":    "   ",               // Key matches secret, but value is whitespace
					"AUTH_MODE":         "oauth2",            // Safe: key is not a secret suffix
					"URL_PREFIX":        "/api/v1",           // Safe: key is not a secret suffix
					"KEY_ROTATION_DAYS": "30",                // Safe: key is not a secret suffix
				},
				Machines: []Machine{
					{
						ID:   "mach-worker",
						Name: "worker-1",
						EnvVariables: map[string]string{
							"API_SECRET_KEY": "sk-live-abc123xyz",
						},
					},
				},
			},
		},
	}

	findings, err := rule.Evaluate(context.Background(), inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should flag DATABASE_URL and STRIPE_API_KEY (app level) plus API_SECRET_KEY (machine level).
	expectedFindings := 3
	if len(findings) != expectedFindings {
		t.Errorf("expected %d findings, got %d", expectedFindings, len(findings))
	}

	for _, f := range findings {
		if strings.Contains(f.Message, "super-secret-password") || strings.Contains(f.Message, "sk_live_") || strings.Contains(f.Message, "sk-live-") {
			t.Errorf("finding message leaked raw secret credentials: %s", f.Message)
		}
	}

	machineFindings := 0
	for _, f := range findings {
		if f.ResourceType == "Machine" && f.ResourceID == "mach-worker" {
			machineFindings++
		}
	}
	if machineFindings != 1 {
		t.Errorf("expected 1 machine-level finding on mach-worker, got %d", machineFindings)
	}
}
