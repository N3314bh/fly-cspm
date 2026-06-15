package scanner

import (
	"context"
	"fmt"
	"sort"

	"github.com/neelabhsarkar/flycspm/pkg/rules"
)

// Scanner orchestrates the configuration loading, fetching, and rule execution.
type Scanner struct {
	rules []rules.Rule
}

// New creates a new scanner configured with the registered rules.
func New() *Scanner {
	return &Scanner{
		rules: rules.GetRules(),
	}
}

// Scan runs the policy engine against a given inventory of resources.
func (s *Scanner) Scan(ctx context.Context, inventory *rules.Inventory) ([]rules.Finding, error) {
	allFindings := make([]rules.Finding, 0)

	for _, rule := range s.rules {
		findings, err := rule.Evaluate(ctx, inventory)
		if err != nil {
			return nil, fmt.Errorf("failed evaluating rule %s (%s): %w", rule.ID(), rule.Name(), err)
		}
		allFindings = append(allFindings, findings...)
	}

	// Sort findings by severity weight (Critical -> High -> Medium -> Low),
	// then deterministically by Rule ID, and finally by Resource ID.
	sort.Slice(allFindings, func(i, j int) bool {
		wI := getSeverityWeight(allFindings[i].Severity)
		wJ := getSeverityWeight(allFindings[j].Severity)
		if wI != wJ {
			return wI < wJ
		}
		if allFindings[i].RuleID != allFindings[j].RuleID {
			return allFindings[i].RuleID < allFindings[j].RuleID
		}
		return allFindings[i].ResourceID < allFindings[j].ResourceID
	})

	return allFindings, nil
}

func getSeverityWeight(sev rules.Severity) int {
	switch sev {
	case rules.SeverityCritical:
		return 1
	case rules.SeverityHigh:
		return 2
	case rules.SeverityMedium:
		return 3
	case rules.SeverityLow:
		return 4
	default:
		return 99 // Put unrecognized severities at the bottom
	}
}
