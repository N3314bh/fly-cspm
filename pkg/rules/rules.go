package rules

import (
	"context"
)

// Severity represents the security risk level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Finding represents an individual security vulnerability or misconfiguration.
type Finding struct {
	RuleID       string   `json:"rule_id"`
	RuleName     string   `json:"rule_name"`
	ResourceID   string   `json:"resource_id"`
	ResourceType string   `json:"resource_type"`
	Severity     Severity `json:"severity"`
	Message      string   `json:"message"`
}

// Rule defines the interface that all security checks must implement.
type Rule interface {
	ID() string
	Name() string
	Description() string
	Severity() Severity
	Evaluate(ctx context.Context, inventory *Inventory) ([]Finding, error)
}

// Inventory acts as the Data Transfer Object (DTO) containing all scanned resources.
// Using a consolidated inventory allows policies to perform correlation checks (e.g. comparing App config to Volumes).
type Inventory struct {
	Apps    []App    `json:"apps"`
	Volumes []Volume `json:"volumes"`
}

// App represents a Fly.io application.
type App struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Organization string            `json:"organization"`
	IsDatabase   bool              `json:"is_database"`
	PublicIPs    []string          `json:"public_ips"`
	EnvVariables map[string]string `json:"env_variables"`
	Machines     []Machine         `json:"machines"`
}

// Machine represents a Fly.io VM instance.
type Machine struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	State        string            `json:"state"`
	Image        string            `json:"image"`
	Privileged   bool              `json:"privileged"`
	Region       string            `json:"region"`
	EnvVariables map[string]string `json:"env_variables"`
	Services     []ServiceTCP      `json:"services"` // Exposed port listeners
}

// ServiceTCP represents a TCP/HTTP port configuration on a Machine.
type ServiceTCP struct {
	InternalPort int      `json:"internal_port"`
	ExternalPort int      `json:"external_port"`
	Handlers     []string `json:"handlers"` // e.g. ["http", "tls"]
}

// Volume represents a Fly.io storage volume.
type Volume struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AppID     string `json:"app_id"`
	State     string `json:"state"`
	SizeGB    int    `json:"size_gb"`
	Encrypted bool   `json:"encrypted"`
}
