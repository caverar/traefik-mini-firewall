package test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

func TestIntegrationGateKeeper(t *testing.T) {
	// 1. Orchestrate the test environment
	t.Log("Step 1: Lifting Docker Compose stack...")
	cmdUp := exec.Command("docker-compose", "up", "-d")
	if output, err := cmdUp.CombinedOutput(); err != nil {
		t.Fatalf("Failed to start Docker Compose: %s\n%s", err, output)
	}

	// Cleanup logic: ensure environment is destroyed even if the test panics
	t.Cleanup(func() {
		t.Log("Cleaning up environment...")
		exec.Command("docker-compose", "down", "-v").Run()
	})

	// 2. Wait for Traefik and Plugin Health
	maxRetries := 10
	ready := false
	for i := 0; i < maxRetries; i++ {
		// We check the rawdata API to ensure our middleware is actually registered
		resp, err := http.Get("http://localhost:8080/api/http/middlewares")
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			if json.Valid(body) { // Basic check that Traefik is answering JSON
				ready = true
				break
			}
		}
		t.Logf("Waiting for Traefik API... (%d/%d)", i+1, maxRetries)
		time.Sleep(2 * time.Second)
	}
	if !ready { t.Fatal("Traefik API timed out") }

	// 3. Intensive Traffic Scenarios
	tests := []struct {
		name           string
		host           string
		expectedStatus int
	}{
		{
			name:           "Positive Case: Allowed Host (allow.local)",
			host:           "allow.local",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Negative Case: Explicitly Blocked Host (block.local)",
			host:           "block.local",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Pattern Case: Wildcard Match Allowed (*.wildcard.local)",
			host:           "test.wildcard.local",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Edge Case: Host not defined in Traefik Routers",
			host:           "random.host.com",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Security Case: Router Match but Policy Default Block",
			host:           "other.local",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Source IP Restriction: Blocked because requester IP is not 192.168.99.x",
			host:           "restricted-ip.local",
			expectedStatus: http.StatusForbidden,
		},
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tc.host // Simulate the Host header

			resp, err := client.Do(req)
			if err != nil { t.Fatalf("Request failed: %v", err) }
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("Host: %s | Expected: %d | Got: %d", tc.host, tc.expectedStatus, resp.StatusCode)
			} else {
				t.Logf("PASS: %s -> %d", tc.host, resp.StatusCode)
			}
		})
	}
}

func TestMain(m *testing.M) {
	fmt.Println("Starting GateKeeper Integration Tests...")
	m.Run()
}