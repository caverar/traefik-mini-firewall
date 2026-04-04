package traefik_mini_firewall

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGateKeeper_ServeHTTP(t *testing.T) {
	// Define test cases
	testCases := []struct {
		desc           string
		config         *Config
		remoteAddr     string // Format "ip:port"
		host           string
		expectedStatus int
	}{
		{
			desc: "Allow IP within CIDR for specific host",
			config: &Config{
				Policies: map[string]Policy{
					"vpn-only": {
						Sources:          []string{"10.0.0.0/24"},
						Action:           "allow",
						DestinationHosts: []string{"internal.local"},
					},
				},
				DefaultPolicy: DefaultPolicy{Action: "block"},
			},
			remoteAddr:     "10.0.0.5:12345",
			host:           "internal.local",
			expectedStatus: http.StatusOK,
		},
		{
			desc: "Block IP within CIDR for specific host",
			config: &Config{
				Policies: map[string]Policy{
					"malicious": {
						Sources:          []string{"192.168.1.100/32"},
						Action:           "block",
						DestinationHosts: []string{"*"},
					},
				},
				DefaultPolicy: DefaultPolicy{Action: "allow", DestinationHosts: []string{"*"}},
			},
			remoteAddr:     "192.168.1.100:5555",
			host:           "any.com",
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "Allow through Wildcard host match",
			config: &Config{
				DefaultPolicy: DefaultPolicy{
					Action:           "allow",
					DestinationHosts: []string{"*.example.com"},
				},
			},
			remoteAddr:     "1.1.1.1:80",
			host:           "sub.example.com",
			expectedStatus: http.StatusOK,
		},
		{
			desc: "Deny when no policy matches (Default Block)",
			config: &Config{
				DefaultPolicy: DefaultPolicy{
					Action:           "block",
					DestinationHosts: []string{"only-this.com"},
				},
			},
			remoteAddr:     "8.8.8.8:443",
			host:           "other.com",
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "Allow via Global Source match",
			config: &Config{
				Policies: map[string]Policy{
					"public": {
						Sources:          []string{"*"},
						Action:           "allow",
						DestinationHosts: []string{"public.me"},
					},
				},
			},
			remoteAddr:     "45.5.5.5:123",
			host:           "public.me",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// 1. Setup the next handler in the chain (the "app")
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// 2. Instantiate the middleware
			ctx := context.Background()
			handler, err := New(ctx, nextHandler, tc.config, "test-gatekeeper")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			// 3. Create a mock request
			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host, nil)
			req.RemoteAddr = tc.remoteAddr
			req.Host = tc.host // httptest might overwrite this from URL, so we set it explicitly

			// 4. Create a response recorder
			rr := httptest.NewRecorder()

			// 5. Execute
			handler.ServeHTTP(rr, req)

			// 6. Assert
			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}

func TestHostMatches(t *testing.T) {
	// POLICY TO TEST
	// policy := InternalPolicy{
	// 	destinationHosts: []string{"exact.com", "*.wildcard.me", "*"},
	// }

	// We check the internal function directly for edge cases
	if !hostMatches("exact.com", InternalPolicy{destinationHosts: []string{"exact.com"}}) {
		t.Error("Should match exact domain")
	}
	if !hostMatches("sub.wildcard.me", InternalPolicy{destinationHosts: []string{"*.wildcard.me"}}) {
		t.Error("Should match subdomain wildcard")
	}
	if !hostMatches("anything.com", InternalPolicy{allHosts: true}) {
		t.Error("Should match total wildcard")
	}
}