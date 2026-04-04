package traefik_mini_firewall

import (
	"context"
	"net"
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
		{
			desc: "Deny when IP is valid but not in allowed CIDR",
			config: &Config{
				Policies: map[string]Policy{
					"private-only": {
						Sources:          []string{"192.168.1.0/24"},
						Action:           "allow",
						DestinationHosts: []string{"private.local"},
					},
				},
				DefaultPolicy: DefaultPolicy{Action: "block", DestinationHosts: []string{"*"}},
			},
			remoteAddr:     "10.0.0.1:1234",
			host:           "private.local",
			expectedStatus: http.StatusForbidden,
		},
		{
			desc: "Allow multiple CIDRs in one policy",
			config: &Config{
				Policies: map[string]Policy{
					"multi-net": {
						Sources:          []string{"10.0.0.0/24", "172.16.0.0/16"},
						Action:           "allow",
						DestinationHosts: []string{"multi.local"},
					},
				},
			},
			remoteAddr:     "172.16.0.50:80",
			host:           "multi.local",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			ctx := context.Background()
			handler, err := New(ctx, nextHandler, tc.config, "test-gatekeeper")
			if err != nil { t.Fatalf("Failed to create middleware: %v", err) }

			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host, nil)
			req.RemoteAddr = tc.remoteAddr
			req.Host = tc.host

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectedStatus { t.Errorf("Expected %d, got %d", tc.expectedStatus, rr.Code) }
		})
	}
}

func TestIPMatches(t *testing.T) {
	_, netA, _ := net.ParseCIDR("10.0.0.0/24")
	_, netB, _ := net.ParseCIDR("192.168.0.0/16")
	p := InternalPolicy{
		networks: []*net.IPNet{netA, netB},
	}

	tests := []struct {
		ip      string
		matches bool
	}{
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"8.8.8.8", false},
		{"10.0.1.1", false},
	}

	for _, tc := range tests {
		if ipMatches(net.ParseIP(tc.ip), p) != tc.matches {
			t.Errorf("IP %s expected match=%v", tc.ip, tc.matches)
		}
	}
}