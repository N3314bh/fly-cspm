package scanner

import (
	"context"
	"testing"

	"github.com/neelabhsarkar/flycspm/pkg/rules"
)

type mockRule struct {
	id       string
	findings []rules.Finding
}

func (m *mockRule) ID() string          { return m.id }
func (m *mockRule) Name() string        { return "Mock Rule" }
func (m *mockRule) Description() string { return "Mock rule description" }
func (m *mockRule) Severity() rules.Severity {
	return rules.SeverityLow
}
func (m *mockRule) Evaluate(ctx context.Context, inv *rules.Inventory) ([]rules.Finding, error) {
	return m.findings, nil
}

func TestScanner_Scan(t *testing.T) {
	mockFindings := []rules.Finding{
		{
			RuleID:       "MOCK-001",
			RuleName:     "Mock Rule",
			ResourceID:   "res-1",
			ResourceType: "App",
			Severity:     rules.SeverityLow,
			Message:      "Mock finding",
		},
	}

	mr := &mockRule{
		id:       "MOCK-001",
		findings: mockFindings,
	}

	// Register the mock rule to rules package registry manually
	rules.Register(mr)

	s := New()

	findings, err := s.Scan(context.Background(), &rules.Inventory{})
	if err != nil {
		t.Fatalf("unexpected error scanning: %v", err)
	}

	// Check if our mock finding was evaluated by the scanner
	foundMock := false
	for _, f := range findings {
		if f.RuleID == "MOCK-001" {
			foundMock = true
			break
		}
	}

	if !foundMock {
		t.Errorf("expected to find mock finding in scanner scan results")
	}
}
