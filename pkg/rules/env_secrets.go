package rules

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
)

func init() {
	Register(&EnvSecrets{})
}

// Go Performance Tip: Pre-compile regexes at package scope to avoid compiling them
// inside the evaluation loop (which runs for every scanned application).
var (
	// Matches key patterns suggesting a secret by checking for suffix or standalone word.
	// E.g., DATABASE_URL, API_KEY, AUTH_TOKEN, password, secret, etc.
	// But excludes: AUTH_MODE, URL_PREFIX, KEY_ROTATION_DAYS.
	secretKeyRegex = regexp.MustCompile(`(?i)([_-](password|secret|token|key|credential|passphrase|auth|url|uri|private)$|^(password|secret|token|key|credential|passphrase|auth|url|uri|private)$)`)

	// Keys that definitely represent credentials or secrets if set (e.g. password, secret, token, passphrase, credential)
	unconditionalSecretKeyRegex = regexp.MustCompile(`(?i)([_-](password|secret|token|passphrase|credential)$|^(password|secret|token|passphrase|credential)$)`)

	// Matches typical placeholder values to reduce false positives (e.g. "change-me", "", "placeholder")
	placeholderRegex = regexp.MustCompile(`(?i)^(change[-_]?me|placeholder|test|dummy|false|true|nil|null|none|default)?$`)

	// Catches connection strings, JWTs, and common API key prefixes by structure
	knownSecretPattern = regexp.MustCompile(
		`(?i)(://[^:]+:[^@]+@|^eyJ[a-zA-Z0-9_-]+\.|^(sk|pk|ghp|ghs|xox[baprs])[-_][a-zA-Z0-9])`,
	)
)

func looksLikeSecret(val string) bool {
	// Structured patterns are high-confidence regardless of length
	if knownSecretPattern.MatchString(val) {
		return true
	}
	// Otherwise require sufficient length + entropy
	return len(val) >= 16 && shannonEntropy(val) >= 3.5
}

func shannonEntropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	var h float64
	n := float64(len(s))
	for _, count := range freq {
		p := count / n
		h -= p * math.Log2(p)
	}
	return h
}

// EnvSecrets audits application configurations for plaintext secrets in environment variables.
type EnvSecrets struct{}

func (r *EnvSecrets) ID() string {
	return "FLY-SEC-001"
}

func (r *EnvSecrets) Name() string {
	return "Plaintext Secrets in Environment Variables"
}

func (r *EnvSecrets) Description() string {
	return "Environment variables are visible in control planes, telemetry, and debugging logs. Sensitive values (like passwords, keys, or tokens) should be stored securely using Fly.io Secrets instead of standard app environment variables."
}

func (r *EnvSecrets) Severity() Severity {
	return SeverityHigh
}

func (r *EnvSecrets) Evaluate(ctx context.Context, inventory *Inventory) ([]Finding, error) {
	var findings []Finding

	for _, app := range inventory.Apps {
		// 1. Audit App-level environment variables
		for key, val := range app.EnvVariables {
			valClean := strings.TrimSpace(val)
			if secretKeyRegex.MatchString(key) {
				if valClean != "" && !placeholderRegex.MatchString(valClean) {
					isSecret := unconditionalSecretKeyRegex.MatchString(key) || looksLikeSecret(valClean)
					if isSecret {
						maskedVal := maskValue(valClean)
						findings = append(findings, Finding{
							RuleID:       r.ID(),
							RuleName:     r.Name(),
							ResourceID:   app.ID,
							ResourceType: "App",
							Severity:     r.Severity(),
							Message:      fmt.Sprintf("Application %q exposes a potential secret in environment variable %q (%s). Use 'fly secrets set' instead.", app.Name, key, maskedVal),
						})
					}
				}
			}
		}

		// 2. Audit Machine-level environment variables
		for _, mach := range app.Machines {
			for key, val := range mach.EnvVariables {
				valClean := strings.TrimSpace(val)
				if secretKeyRegex.MatchString(key) {
					if valClean != "" && !placeholderRegex.MatchString(valClean) {
						isSecret := unconditionalSecretKeyRegex.MatchString(key) || looksLikeSecret(valClean)
						if isSecret {
							maskedVal := maskValue(valClean)
							findings = append(findings, Finding{
								RuleID:       r.ID(),
								RuleName:     r.Name(),
								ResourceID:   mach.ID,
								ResourceType: "Machine",
								Severity:     r.Severity(),
								Message:      fmt.Sprintf("Machine %q (%s) in application %q exposes a potential secret in environment variable %q (%s). Use 'fly secrets set' instead.", mach.Name, mach.ID, app.Name, key, maskedVal),
							})
						}
					}
				}
			}
		}
	}

	return findings, nil
}

// maskValue prevents leaking sensitive variables into scanner output logs
func maskValue(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	// Show first and last characters, mask the middle
	return fmt.Sprintf("%c***%c", val[0], val[len(val)-1])
}
