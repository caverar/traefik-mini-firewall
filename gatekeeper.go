package traefik_mini_firewall

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

type Config struct {
	DefaultPolicy DefaultPolicy     `json:"defaultPolicy,omitempty"`
	Policies      map[string]Policy `json:"policies,omitempty"`
}

type Policy struct {
	Sources          []string `json:"sources,omitempty"`
	Action           string   `json:"action,omitempty"`
	DestinationHosts []string `json:"destinationHosts,omitempty"`
}

type DefaultPolicy struct {
	Action           string   `json:"action,omitempty"`
	DestinationHosts []string `json:"destinationHosts,omitempty"`
}

type InternalPolicy struct {
	name             string
	allSources       bool
	networks         []*net.IPNet
	action           string
	allHosts         bool
	destinationHosts []string
}

type GateKeeper struct {
	next             http.Handler
	name             string
	internalPolicies []InternalPolicy
}

func CreateConfig() *Config {
	return &Config{
		DefaultPolicy: DefaultPolicy{Action: "block"},
		Policies:      make(map[string]Policy),
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (
    http.Handler, error,
) {
	gk := &GateKeeper{
		next: next,
		name: name,
	}

	parsePolicy := func(name string, p Policy) InternalPolicy {
		ipNets := []*net.IPNet{}
		allSrc, allDst := false, false

		for _, s := range p.Sources {
			if s == "*" {
				allSrc = true
				break
			}
			_, ipNet, err := net.ParseCIDR(s)
			if err == nil {
				ipNets = append(ipNets, ipNet)
			}
		}

		for _, h := range p.DestinationHosts {
			if h == "*" {
				allDst = true
				break
			}
		}

		return InternalPolicy{
			name:             name,
			allSources:       allSrc,
			networks:         ipNets,
			action:           p.Action,
			allHosts:         allDst,
			destinationHosts: p.DestinationHosts,
		}
	}

	// 1. Load specific policies first
	for pName, p := range config.Policies {
		gk.internalPolicies = append(gk.internalPolicies, parsePolicy(pName, p))
	}

	// 2. Append DefaultPolicy at the end as a catch-all (*)
	gk.internalPolicies = append(gk.internalPolicies, parsePolicy("default", Policy{
		Action:           config.DefaultPolicy.Action,
		DestinationHosts: config.DefaultPolicy.DestinationHosts,
		Sources:          []string{"*"},
	}))

	return gk, nil
}

func ipMatches(ip net.IP, p InternalPolicy) bool {
	if p.allSources { return true }
	for _, network := range p.networks {
		if network.Contains(ip) { return true }
	}
	return false
}

func hostMatches(host string, p InternalPolicy) bool {
	if p.allHosts { return true }
	for _, pattern := range p.destinationHosts {
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(host, suffix) { return true }
		}
		if host == pattern { return true }
	}
	return false
}

func (a *GateKeeper) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

    // Intended for real ip matching, this not replace a proper firewall
	originIPStr, _, _ := net.SplitHostPort(req.RemoteAddr)
	originIP := net.ParseIP(originIPStr)
	targetHost := req.Host

	// Policy matching order:
	for _, policy := range a.internalPolicies {
		if ipMatches(originIP, policy) {
			if hostMatches(targetHost, policy) {
				if policy.action == "allow" {
					a.next.ServeHTTP(rw, req)
					return
				}
				fmt.Fprintf(
                    os.Stdout,
                    "[GateKeeper] BLOCK: IP %s matched policy '%s' for host %s\n",
                    originIPStr,
                    policy.name,
                    targetHost,
                )
				http.Error(rw, "Forbidden by GateKeeper: "+policy.name, http.StatusForbidden)
				return
			}
		}
	}

    // Fallback
	fmt.Fprintf(
        os.Stdout,
        "[GateKeeper] DENY: No policy matched for IP %s and host %s\n",
        originIPStr,
        targetHost,
    )
	http.Error(
        rw,
        "Access Denied: No security group rule matches your request.",
        http.StatusForbidden,
    )
}