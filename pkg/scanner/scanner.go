package scanner

import (
	"context"
	"fmt"

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
	var allFindings []rules.Finding

	for _, rule := range s.rules {
		findings, err := rule.Evaluate(ctx, inventory)
		if err != nil {
			return nil, fmt.Errorf("failed evaluating rule %s (%s): %w", rule.ID(), rule.Name(), err)
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}
