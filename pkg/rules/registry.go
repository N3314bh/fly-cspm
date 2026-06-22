package rules

import (
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Rule)
)

// Register registers a new rule to the global scanning registry.
// This is typically called from the rule package's init() function.
func Register(rule Rule) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[rule.ID()] = rule
}

// GetRules returns a list of all registered security rules.
func GetRules() []Rule {
	registryMu.RLock()
	defer registryMu.RUnlock()

	rules := make([]Rule, 0, len(registry))
	for _, rule := range registry {
		rules = append(rules, rule)
	}
	return rules
}
