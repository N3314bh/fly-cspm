package flyapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/neelabhsarkar/flycspm/pkg/rules"
)

// DefaultEndpoint is the official Fly.io GraphQL endpoint.
const DefaultEndpoint = "https://api.fly.io/graphql"

// DefaultMachinesEndpoint is the official Fly.io Machines REST endpoint.
const DefaultMachinesEndpoint = "https://api.machines.dev/v1"

// Client interacts with the Fly.io API.
type Client struct {
	token            string
	endpoint         string
	machinesEndpoint string
	httpClient       *http.Client
}

// Option allows configuring the API Client.
type Option func(*Client)

// WithEndpoint overrides the default API endpoint (useful for testing).
func WithEndpoint(url string) Option {
	return func(c *Client) {
		c.endpoint = url
	}
}

// WithMachinesEndpoint overrides the default Machines API endpoint (useful for testing).
func WithMachinesEndpoint(url string) Option {
	return func(c *Client) {
		c.machinesEndpoint = url
	}
}

// NewClient creates a new Fly.io API client.
func NewClient(token string, opts ...Option) *Client {
	c := &Client{
		token:            token,
		endpoint:         DefaultEndpoint,
		machinesEndpoint: DefaultMachinesEndpoint,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// gqlRequest represents a standard GraphQL POST payload.
type gqlRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// FetchInventory queries the Fly.io GraphQL endpoint and maps the resources
// to our unified rules.Inventory schema.
func (c *Client) FetchInventory(ctx context.Context) (*rules.Inventory, error) {
	query := `
	query($after: String) {
		apps(first: 100, after: $after) {
			pageInfo {
				hasNextPage
				endCursor
			}
			nodes {
				id
				name
				isDatabase
				organization {
					slug
				}
				ipAddresses {
					nodes {
						address
						type
					}
				}
				config {
					definition
				}
			}
		}
	}`

	inventory := &rules.Inventory{
		Apps:    []rules.App{},
		Volumes: []rules.Volume{},
	}

	var after *string

	for {
		var response struct {
			Data struct {
				Apps struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						ID           string `json:"id"`
						Name         string `json:"name"`
						IsDatabase   bool   `json:"isDatabase"`
						Organization struct {
							Slug string `json:"slug"`
						} `json:"organization"`
						IPAddresses struct {
							Nodes []struct {
								Address string `json:"address"`
								Type    string `json:"type"`
							} `json:"nodes"`
						} `json:"ipAddresses"`
						Config *struct {
							Definition json.RawMessage `json:"definition"`
						} `json:"config"`
					} `json:"nodes"`
				} `json:"apps"`
			} `json:"data"`
		}

		variables := make(map[string]interface{})
		if after != nil {
			variables["after"] = *after
		}

		err := c.post(ctx, query, variables, &response)
		if err != nil {
			return nil, fmt.Errorf("fly api request failed: %w", err)
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			gErr error
		)

		nodesCount := len(response.Data.Apps.Nodes)
		apps := make([]rules.App, nodesCount)
		volsList := make([][]rules.Volume, nodesCount)

		for idx, appNode := range response.Data.Apps.Nodes {
			mu.Lock()
			if gErr != nil {
				mu.Unlock()
				break
			}
			mu.Unlock()

			appNode := appNode // safe copy for closure in goroutine
			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				// Early-break check within the goroutine body to avoid starting work
				mu.Lock()
				if gErr != nil {
					mu.Unlock()
					return
				}
				mu.Unlock()

				var ips []string
				for _, ip := range appNode.IPAddresses.Nodes {
					// Fly.io marks public IPs as "v4" or "v6". Private internal IPs (6PN) start with fdaa.
					if ip.Type == "v4" || ip.Type == "v6" {
						ips = append(ips, ip.Address)
					}
				}

				// Parse config environment variables
				envVars := make(map[string]string)
				if appNode.Config != nil && len(appNode.Config.Definition) > 0 {
					var appDef struct {
						Env map[string]interface{} `json:"env"`
					}
					if err := json.Unmarshal(appNode.Config.Definition, &appDef); err == nil {
						for k, v := range appDef.Env {
							if v != nil {
								envVars[k] = fmt.Sprintf("%v", v)
							}
						}
					}
				}

				// Fetch machines via REST API
				machines, machIsDb, err := c.fetchMachines(ctx, appNode.Name)
				if err != nil {
					mu.Lock()
					if gErr == nil {
						gErr = err
						cancel()
					}
					mu.Unlock()
					return
				}

				// Parse volumes (appended to top-level inventory)
				vols, err := c.fetchVolumes(ctx, appNode.ID, appNode.Name)
				if err != nil {
					mu.Lock()
					if gErr == nil {
						gErr = err
						cancel()
					}
					mu.Unlock()
					return
				}

				apps[i] = rules.App{
					ID:           appNode.ID,
					Name:         appNode.Name,
					Organization: appNode.Organization.Slug,
					IsDatabase:   appNode.IsDatabase || machIsDb,
					PublicIPs:    ips,
					EnvVariables: envVars,
					Machines:     machines,
				}
				volsList[i] = vols
			}(idx)
		}

		wg.Wait()

		if gErr != nil {
			return nil, gErr
		}

		// Append the fetched apps and volumes in order
		for i := 0; i < nodesCount; i++ {
			if apps[i].ID == "" {
				continue
			}
			inventory.Apps = append(inventory.Apps, apps[i])
			inventory.Volumes = append(inventory.Volumes, volsList[i]...)
		}

		if !response.Data.Apps.PageInfo.HasNextPage {
			break
		}
		cursor := response.Data.Apps.PageInfo.EndCursor
		after = &cursor
	}

	return inventory, nil
}

func isDatabaseImage(image string) bool {
	dbKeywords := []string{"postgres", "redis", "mysql", "mariadb", "mongodb", "timescaledb"}
	lowerImage := strings.ToLower(image)
	for _, kw := range dbKeywords {
		if strings.Contains(lowerImage, kw) {
			return true
		}
	}
	return false
}

// post helper executes the HTTP request and handles authentication headers.
func (c *Client) post(ctx context.Context, query string, variables map[string]interface{}, out interface{}) error {
	reqBody, err := json.Marshal(gqlRequest{Query: query, Variables: variables})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Check for GraphQL errors
	var errWrapper struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(bodyBytes, &errWrapper); err == nil && len(errWrapper.Errors) > 0 {
		var errMsgs []string
		for _, e := range errWrapper.Errors {
			errMsgs = append(errMsgs, e.Message)
		}
		return fmt.Errorf("graphql error: %s", strings.Join(errMsgs, "; "))
	}

	return json.Unmarshal(bodyBytes, out)
}

func (c *Client) fetchVolumes(ctx context.Context, appID string, appName string) ([]rules.Volume, error) {
	url := fmt.Sprintf("%s/apps/%s/volumes", c.machinesEndpoint, appName)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("machines API returned status %d", resp.StatusCode)
	}

	var rawVolumes []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		State     string `json:"state"`
		SizeGB    int    `json:"size_gb"`
		Encrypted bool   `json:"encrypted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawVolumes); err != nil {
		return nil, err
	}

	var volumes []rules.Volume
	for _, rv := range rawVolumes {
		volumes = append(volumes, rules.Volume{
			ID:        rv.ID,
			Name:      rv.Name,
			AppID:     appID,
			State:     rv.State,
			SizeGB:    rv.SizeGB,
			Encrypted: rv.Encrypted,
		})
	}
	return volumes, nil
}

func (c *Client) fetchMachines(ctx context.Context, appName string) ([]rules.Machine, bool, error) {
	url := fmt.Sprintf("%s/apps/%s/machines", c.machinesEndpoint, appName)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("machines API returned status %d", resp.StatusCode)
	}

	var rawMachines []struct {
		ID     string          `json:"id"`
		Name   string          `json:"name"`
		State  string          `json:"state"`
		Region string          `json:"region"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawMachines); err != nil {
		return nil, false, err
	}

	var machines []rules.Machine
	var isDatabase bool

	for _, rm := range rawMachines {
		var machConfig struct {
			Image    string                 `json:"image"`
			Metadata map[string]string      `json:"metadata"`
			Env      map[string]interface{} `json:"env"`
			Init     *struct {
				Privileged bool `json:"privileged"`
			} `json:"init"`
			Services []struct {
				InternalPort int `json:"internal_port"`
				Ports        []struct {
					Port     int      `json:"port"`
					Handlers []string `json:"handlers"`
				} `json:"ports"`
			} `json:"services"`
		}

		var privileged bool
		var image string
		var services []rules.ServiceTCP
		machEnv := make(map[string]string)

		if len(rm.Config) > 0 {
			if err := json.Unmarshal(rm.Config, &machConfig); err == nil {
				image = machConfig.Image
				if machConfig.Init != nil {
					privileged = machConfig.Init.Privileged
				}
				// Identify database app using metadata or image keywords
				if isDatabaseImage(image) || machConfig.Metadata["fly-managed-postgres"] == "true" || machConfig.Metadata["fly_app_role"] == "postgres_cluster" {
					isDatabase = true
				}
				// Merge env variables
				for k, v := range machConfig.Env {
					if v != nil {
						machEnv[k] = fmt.Sprintf("%v", v)
					}
				}
				// Map services and flatten external ports
				for _, srv := range machConfig.Services {
					for _, p := range srv.Ports {
						services = append(services, rules.ServiceTCP{
							InternalPort: srv.InternalPort,
							ExternalPort: p.Port,
							Handlers:     p.Handlers,
						})
					}
				}
			}
		}

		machines = append(machines, rules.Machine{
			ID:           rm.ID,
			Name:         rm.Name,
			State:        rm.State,
			Image:        image,
			Privileged:   privileged,
			Region:       rm.Region,
			EnvVariables: machEnv,
			Services:     services,
		})
	}

	return machines, isDatabase, nil
}
