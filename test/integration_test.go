package test

import (
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

func TestIntegrationGateKeeper(t *testing.T) {
	// 1. Start the test environment using Docker Compose
	t.Log("Starting test environment with Docker Compose...")
	cmdUp := exec.Command("docker-compose", "up", "-d")
	if output, err := cmdUp.CombinedOutput(); err != nil {
		t.Fatalf("Failed to start environment: %s\n%s", err, output)
	}

	// Ensure cleanup after the test finishes
	t.Cleanup(func() {
		t.Log("Cleaning up environment...")
		exec.Command("docker-compose", "down", "-v").Run()
	})

	// 2. Wait for Traefik and the plugin to be initialized
	maxRetries := 10
	ready := false
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get("http://localhost:8080/api/rawdata")
		if err == nil && resp.StatusCode == http.StatusOK {
			ready = true
			break
		}
		t.Logf("Waiting for Traefik API... (Attempt %d/%d)", i+1, maxRetries)
		time.Sleep(2 * time.Second)
	}
	if !ready {
		t.Fatal("Traefik did not become ready in time")
	}

	// 3. Define Intensive Test Cases
	tests := []struct {
		name           string
		host           string
		expectedStatus int
	}{
		{
			name:           "Exact Match - Allowed",
			host:           "allow.local",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Exact Match - Blocked",
			host:           "block.local",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Wildcard Match - Allowed",
			host:           "test.wildcard.local",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Default Policy - Blocked (No router match)",
			host:           "random.host.com",
			expectedStatus: http.StatusNotFound, // Traefik returns 404 if no router matches
		},
		{
			name:           "Default Policy - Blocked (Router match, but no policy match)",
			host:           "other.local",
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
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("[%s] Expected status %d, got %d", tc.host, tc.expectedStatus, resp.StatusCode)
			} else {
				t.Logf("[%s] Received expected status: %d", tc.host, resp.StatusCode)
			}
		})
	}
}

func TestMain(m *testing.M) {
	fmt.Println("Starting GateKeeper Integration Tests...")
	m.Run()
}