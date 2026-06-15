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

func TestScanner_Scan_Sorting(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "RULE-C", ResourceID: "res-3", Severity: rules.SeverityLow},
		{RuleID: "RULE-A", ResourceID: "res-1", Severity: rules.SeverityCritical},
		{RuleID: "RULE-B", ResourceID: "res-2", Severity: rules.SeverityHigh},
		{RuleID: "RULE-A", ResourceID: "res-2", Severity: rules.SeverityCritical},
		{RuleID: "RULE-D", ResourceID: "res-1", Severity: rules.SeverityMedium},
	}

	mr := &mockRule{
		id:       "SORT-MOCK",
		findings: findings,
	}

	s := &Scanner{
		rules: []rules.Rule{mr},
	}

	sorted, err := s.Scan(context.Background(), &rules.Inventory{})
	if err != nil {
		t.Fatalf("unexpected error scanning: %v", err)
	}

	if len(sorted) != len(findings) {
		t.Fatalf("expected %d findings, got %d", len(findings), len(sorted))
	}

	expected := []struct {
		severity rules.Severity
		ruleID   string
		resource string
	}{
		{rules.SeverityCritical, "RULE-A", "res-1"},
		{rules.SeverityCritical, "RULE-A", "res-2"},
		{rules.SeverityHigh, "RULE-B", "res-2"},
		{rules.SeverityMedium, "RULE-D", "res-1"},
		{rules.SeverityLow, "RULE-C", "res-3"},
	}

	for i, exp := range expected {
		if sorted[i].Severity != exp.severity || sorted[i].RuleID != exp.ruleID || sorted[i].ResourceID != exp.resource {
			t.Errorf("at index %d: expected {%s, %s, %s}, got {%s, %s, %s}",
				i, exp.severity, exp.ruleID, exp.resource,
				sorted[i].Severity, sorted[i].RuleID, sorted[i].ResourceID)
		}
	}
}
