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
	flag.Parse()

	var inventory *rules.Inventory
	var err error

	// 1. Determine scanning mode
	if *filePath != "" {
		// Offline scan mode
		fmt.Printf("Starting Offline CSPM Scan using file: %s...\n", *filePath)
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

		fmt.Println("Starting Live Fly.io CSPM Scan...")
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
		fmt.Printf("Filtered inventory to %d apps matching %q\n", len(inventory.Apps), *filter)
	}

	// 2. Execute Scan
	s := scanner.New()
	findings, err := s.Scan(context.Background(), inventory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scanning error: %v\n", err)
		os.Exit(1)
	}

	// 3. Report Findings
	printReport(findings)

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

func printReport(findings []rules.Finding) {
	fmt.Printf("\n--- Fly.io CSPM Scan Results ---\n")
	fmt.Printf("Total Findings: %d\n\n", len(findings))

	for i, f := range findings {
		fmt.Printf("[%d] %s: %s\n", i+1, f.Severity, f.RuleName)
		fmt.Printf("    Rule ID:  %s\n", f.RuleID)
		fmt.Printf("    Resource: %s (%s)\n", f.ResourceID, f.ResourceType)
		fmt.Printf("    Details:  %s\n\n", f.Message)
	}
}
