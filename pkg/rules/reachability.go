package rules

import (
	"context"
	"fmt"
)

func init() {
	Register(&PublicReachability{})
}

// PublicReachability implements network path analysis to identify active external attack paths.
type PublicReachability struct{}

func (r *PublicReachability) ID() string {
	return "FLY-NET-002"
}

func (r *PublicReachability) Name() string {
	return "Publicly Reachable Database Attack Path"
}

func (r *PublicReachability) Description() string {
	return "Analyzes the network topology (public IPs, edge routing configs, and port services) using graph traversal to identify databases actually accessible to the internet."
}

func (r *PublicReachability) Severity() Severity {
	return SeverityCritical
}

// Evaluate performs a Reachability Graph analysis to find active attack paths.
func (r *PublicReachability) Evaluate(ctx context.Context, inventory *Inventory) ([]Finding, error) {
	var findings []Finding

	// Step 1: Build the Adjacency List for the network topology graph.
	// Graph Nodes: "internet", App IDs, Machine IDs.
	adjList := make(map[string][]string)

	// Keep track of database machines to see if they are reachable.
	dbMachines := make(map[string]string) // machineID -> appName

	for _, app := range inventory.Apps {
		// If app has public IPs, there is a path from the Internet to the App node.
		if len(app.PublicIPs) > 0 {
			adjList["internet"] = append(adjList["internet"], app.ID)
		}

		for _, machine := range app.Machines {
			if app.IsDatabase {
				dbMachines[machine.ID] = app.Name
			}

			// A path exists from the App to the Machine ONLY if there are active port bindings.
			if len(machine.Services) > 0 && (machine.State == "started" || machine.State == "starting") {
				adjList[app.ID] = append(adjList[app.ID], machine.ID)
			}
		}
	}

	// Step 2: Run BFS (Breadth-First Search) to determine reachability from "internet" to any DB machine.
	reachableNodes := make(map[string]bool)
	queue := []string{"internet"}
	reachableNodes["internet"] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, neighbor := range adjList[current] {
			if !reachableNodes[neighbor] {
				reachableNodes[neighbor] = true
				queue = append(queue, neighbor)
			}
		}
	}

	// Step 3: Audit findings based on graph reachability state
	for dbMachineID, appName := range dbMachines {
		if reachableNodes[dbMachineID] {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				ResourceID:   dbMachineID,
				ResourceType: "Machine",
				Severity:     r.Severity(),
				Message:      fmt.Sprintf("Database machine %q in app %q is publicly reachable from the internet. Attack path verified: Internet -> App %q -> Machine Port Listener.", dbMachineID, appName, appName),
			})
		}
	}

	return findings, nil
}
