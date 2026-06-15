package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/neelabhsarkar/flycspm/pkg/flyapi"
	"github.com/neelabhsarkar/flycspm/pkg/rules"
	"github.com/neelabhsarkar/flycspm/pkg/scanner"
)

func main() {
	filePath := flag.String("file", "", "Path to the Fly.io inventory JSON file to scan (offline mode)")
	filter := flag.String("filter", "", "Substring to filter App names by (case-insensitive)")
	format := flag.String("format", "text", "Output format: text or json")
	flag.Parse()

	if *format != "text" && *format != "json" {
		fmt.Fprintf(os.Stderr, "Error: invalid format %q. Allowed values: text, json\n", *format)
		flag.Usage()
		os.Exit(1)
	}

	var inventory *rules.Inventory
	var err error

	// 1. Determine scanning mode
	if *filePath != "" {
		// Offline scan mode
		fmt.Fprintf(os.Stderr, "Starting Offline CSPM Scan using file: %s...\n", *filePath)
		inventory, err = loadInventoryFromFile(*filePath)
	} else {
		// Live API scan mode
		token := os.Getenv("FLY_API_TOKEN")
		if token == "" {
			// Try to retrieve token from flyctl auth token
			out, err := exec.Command("fly", "auth", "token").Output()
			if err == nil {
				token = strings.TrimSpace(string(out))
			}
		}

		if token == "" {
			fmt.Fprintln(os.Stderr, "Error: To run a live scan, log in via 'fly auth login' or set 'FLY_API_TOKEN'.")
			fmt.Fprintln(os.Stderr, "Alternatively, specify an offline file using the '--file' flag.")
			flag.Usage()
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, "Starting Live Fly.io CSPM Scan...")
		client := flyapi.NewClient(token)
		inventory, err = client.FetchInventory(context.Background())
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration retrieval failed: %v\n", err)
		os.Exit(1)
	}

	// Filter inventory if filter flag is specified
	if *filter != "" {
		lowerFilter := strings.ToLower(*filter)
		var filteredApps []rules.App
		var filteredVolumes []rules.Volume
		allowedAppIDs := make(map[string]bool)

		for _, app := range inventory.Apps {
			if strings.Contains(strings.ToLower(app.Name), lowerFilter) {
				filteredApps = append(filteredApps, app)
				allowedAppIDs[app.ID] = true
			}
		}

		for _, vol := range inventory.Volumes {
			if allowedAppIDs[vol.AppID] {
				filteredVolumes = append(filteredVolumes, vol)
			}
		}

		inventory.Apps = filteredApps
		inventory.Volumes = filteredVolumes
		fmt.Fprintf(os.Stderr, "Filtered inventory to %d apps matching %q\n", len(inventory.Apps), *filter)
	}

	// 2. Execute Scan
	s := scanner.New()
	findings, err := s.Scan(context.Background(), inventory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scanning error: %v\n", err)
		os.Exit(1)
	}

	// 3. Report Findings
	if *format == "json" {
		data, err := json.MarshalIndent(findings, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal JSON findings: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		printReport(findings)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}

func loadInventoryFromFile(path string) (*rules.Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var inventory rules.Inventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		return nil, err
	}

	return &inventory, nil
}

func isTTY() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func printReport(findings []rules.Finding) {
	var (
		colorReset   = ""
		colorRed     = ""
		colorYellow  = ""
		colorBlue    = ""
		colorGreen   = ""
		colorBold    = ""
		colorRedBold = ""
	)

	if isTTY() {
		colorReset   = "\033[0m"
		colorRed     = "\033[31m"
		colorYellow  = "\033[33m"
		colorBlue    = "\033[34m"
		colorGreen   = "\033[32m"
		colorBold    = "\033[1m"
		colorRedBold = "\033[1;31m"
	}

	fmt.Printf("\n%s--- Fly.io CSPM Scan Results ---%s\n", colorBold, colorReset)

	if len(findings) == 0 {
		fmt.Printf("Total Findings: %s0 (No security issues found)%s\n\n", colorGreen, colorReset)
		return
	}

	// Count severities
	var criticalCount, highCount, mediumCount, lowCount int
	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			criticalCount++
		case rules.SeverityHigh:
			highCount++
		case rules.SeverityMedium:
			mediumCount++
		case rules.SeverityLow:
			lowCount++
		}
	}

	fmt.Printf("Total Findings: %s%d%s (", colorBold, len(findings), colorReset)
	var summaryParts []string
	if criticalCount > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%s%d CRITICAL%s", colorRedBold, criticalCount, colorReset))
	}
	if highCount > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%s%d HIGH%s", colorRed, highCount, colorReset))
	}
	if mediumCount > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%s%d MEDIUM%s", colorYellow, mediumCount, colorReset))
	}
	if lowCount > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%s%d LOW%s", colorBlue, lowCount, colorReset))
	}
	fmt.Print(strings.Join(summaryParts, ", "))
	fmt.Print(")\n\n")

	for i, f := range findings {
		var severityColor string
		switch f.Severity {
		case rules.SeverityCritical:
			severityColor = colorRedBold
		case rules.SeverityHigh:
			severityColor = colorRed
		case rules.SeverityMedium:
			severityColor = colorYellow
		case rules.SeverityLow:
			severityColor = colorBlue
		default:
			severityColor = colorReset
		}

		fmt.Printf("[%d] %s%s%s: %s%s%s\n", i+1, severityColor, f.Severity, colorReset, colorBold, f.RuleName, colorReset)
		fmt.Printf("    Rule ID:  %s\n", f.RuleID)
		fmt.Printf("    Resource: %s (%s)\n", f.ResourceID, f.ResourceType)
		fmt.Printf("    Details:  %s\n\n", f.Message)
	}
}
