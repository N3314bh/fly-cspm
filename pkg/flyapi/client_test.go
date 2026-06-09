package flyapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_FetchInventory(t *testing.T) {
	// Create a local test mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Verify Request headers
		if r.Header.Get("Authorization") != "Bearer mock-token-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == "GET" {
			if r.URL.Path == "/apps/test-app-name/volumes" {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `[
					{
						"id": "vol-test-id",
						"name": "test-volume",
						"state": "attached",
						"size_gb": 50,
						"encrypted": true
					}
				]`)
				return
			}
			if r.URL.Path == "/apps/test-app-name/machines" {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `[
					{
						"id": "mac-test-id",
						"name": "test-machine",
						"state": "started",
						"region": "ams",
						"config": {
							"image": "my-custom-image:latest",
							"metadata": {
								"fly-managed-postgres": "true"
							},
							"init": {
								"privileged": true
							},
							"env": {
								"LOG_LEVEL": "debug",
								"PORT": 8080
							},
							"services": [
								{
									"internal_port": 5432,
									"ports": [
										{ "port": 5432, "handlers": [] },
										{ "port": 15432, "handlers": ["tls"] }
									]
								}
							]
						}
					}
				]`)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// 2. Mock Fly.io API response body
		responseJSON := `{
			"data": {
				"apps": {
					"pageInfo": {
						"hasNextPage": false,
						"endCursor": ""
					},
					"nodes": [
						{
							"id": "app-test-id",
							"name": "test-app-name",
							"isDatabase": false,
							"organization": { "slug": "test-org" },
							"ipAddresses": {
								"nodes": [
									{ "address": "1.2.3.4", "type": "v4" },
									{ "address": "fdaa:0:3b::3", "type": "private" }
								]
							}
						},
						{
							"id": "app-test-db-only-gql",
							"name": "test-db-app-only-gql",
							"isDatabase": true,
							"organization": { "slug": "test-org" },
							"ipAddresses": {
								"nodes": []
							}
						}
					]
				}
			}
		}`

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, responseJSON)
	}))
	defer server.Close()

	// Initialize the client configured to hit our mock HTTP server
	client := NewClient("mock-token-123", WithEndpoint(server.URL), WithMachinesEndpoint(server.URL))

	// Execute Fetch
	inventory, err := client.FetchInventory(context.Background())
	if err != nil {
		t.Fatalf("unexpected client fetch error: %v", err)
	}

	// Assert mapping outputs
	if len(inventory.Apps) != 2 {
		t.Fatalf("expected 2 apps mapped, got %d", len(inventory.Apps))
	}

	app := inventory.Apps[0]
	if app.ID != "app-test-id" {
		t.Errorf("expected app ID 'app-test-id', got '%s'", app.ID)
	}
	if app.Name != "test-app-name" {
		t.Errorf("expected app name 'test-app-name', got '%s'", app.Name)
	}
	if app.Organization != "test-org" {
		t.Errorf("expected organization slug 'test-org', got '%s'", app.Organization)
	}

	// Verify that the private fdaa IP was filtered out, and only public 1.2.3.4 was kept
	if len(app.PublicIPs) != 1 || app.PublicIPs[0] != "1.2.3.4" {
		t.Errorf("expected only public IP '1.2.3.4' to be parsed, got %v", app.PublicIPs)
	}

	// Verify IsDatabase is true due to metadata signal
	if !app.IsDatabase {
		t.Errorf("expected IsDatabase to be true (since metadata contains fly-managed-postgres)")
	}

	// Verify EnvVariables (empty because they are not merged from machines anymore)
	if len(app.EnvVariables) != 0 {
		t.Errorf("expected 0 app env vars, got %d", len(app.EnvVariables))
	}

	// Verify Machines
	if len(app.Machines) != 1 {
		t.Fatalf("expected 1 machine, got %d", len(app.Machines))
	}
	mach := app.Machines[0]
	if mach.ID != "mac-test-id" {
		t.Errorf("expected machine ID 'mac-test-id', got '%s'", mach.ID)
	}
	if mach.Image != "my-custom-image:latest" {
		t.Errorf("expected machine image 'my-custom-image:latest', got '%s'", mach.Image)
	}

	// Verify machine-level EnvVariables
	if len(mach.EnvVariables) != 2 {
		t.Errorf("expected 2 machine env vars, got %d", len(mach.EnvVariables))
	}
	if mach.EnvVariables["LOG_LEVEL"] != "debug" {
		t.Errorf("expected machine LOG_LEVEL='debug', got '%s'", mach.EnvVariables["LOG_LEVEL"])
	}
	if !mach.Privileged {
		t.Errorf("expected machine privileged to be true")
	}

	// Verify Services flattened correctly
	if len(mach.Services) != 2 {
		t.Fatalf("expected 2 mapped services (flattened external ports), got %d", len(mach.Services))
	}
	s1 := mach.Services[0]
	if s1.InternalPort != 5432 || s1.ExternalPort != 5432 || len(s1.Handlers) != 0 {
		t.Errorf("unexpected service 1 configuration: %+v", s1)
	}
	s2 := mach.Services[1]
	if s2.InternalPort != 5432 || s2.ExternalPort != 15432 || len(s2.Handlers) != 1 || s2.Handlers[0] != "tls" {
		t.Errorf("unexpected service 2 configuration: %+v", s2)
	}

	// Verify Volumes (appended to top-level inventory)
	if len(inventory.Volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(inventory.Volumes))
	}
	vol := inventory.Volumes[0]
	if vol.ID != "vol-test-id" {
		t.Errorf("expected volume ID 'vol-test-id', got '%s'", vol.ID)
	}
	if vol.AppID != "app-test-id" {
		t.Errorf("expected volume app ID 'app-test-id', got '%s'", vol.AppID)
	}
	if vol.SizeGB != 50 {
		t.Errorf("expected volume size 50 GB, got %d", vol.SizeGB)
	}
	if !vol.Encrypted {
		t.Errorf("expected volume encrypted to be true")
	}

	// Verify that the second app (only GQL isDatabase) is mapped correctly
	app2 := inventory.Apps[1]
	if app2.ID != "app-test-db-only-gql" {
		t.Errorf("expected app2 ID 'app-test-db-only-gql', got '%s'", app2.ID)
	}
	if app2.Name != "test-db-app-only-gql" {
		t.Errorf("expected app2 name 'test-db-app-only-gql', got '%s'", app2.Name)
	}
	if !app2.IsDatabase {
		t.Errorf("expected app2.IsDatabase to be true (since GraphQL isDatabase is true)")
	}
	if len(app2.Machines) != 0 {
		t.Errorf("expected 0 machines for app2, got %d", len(app2.Machines))
	}
	if len(app2.PublicIPs) != 0 {
		t.Errorf("expected 0 public IPs for app2, got %d", len(app2.PublicIPs))
	}
	if len(app2.EnvVariables) != 0 {
		t.Errorf("expected 0 env variables for app2, got %d", len(app2.EnvVariables))
	}
}
