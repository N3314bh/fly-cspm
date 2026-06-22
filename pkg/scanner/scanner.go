package scanner

import (
	"context"
	"fmt"
	"sort"
	"sync"

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

// Scan runs the policy engine against a given inventory of resources concurrently.
func (s *Scanner) Scan(ctx context.Context, inventory *rules.Inventory) ([]rules.Finding, error) {
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		allFindings []rules.Finding
		errs        []error
	)

	for _, r := range s.rules {
		wg.Add(1)
		go func(rule rules.Rule) {
			defer wg.Done()

			// Check context cancellation before running the rule
			if err := ctx.Err(); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}

			findings, err := rule.Evaluate(ctx, inventory)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("failed evaluating rule %s (%s): %w", rule.ID(), rule.Name(), err))
				return
			}
			allFindings = append(allFindings, findings...)
		}(r)
	}

	wg.Wait()

	if len(errs) > 0 {
		return nil, errs[0] // Return the first encountered error
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
