# WARNING: This is a work in progress, use at your own risk.

# IP Host GateKeeper (Traefik Middleware)

IP Host GateKeeper is a Traefik middleware plugin that enforces Layer 7 access control policies based on:

- Source IP (CIDR ranges)
- Destination host (exact or wildcard match)

It behaves similarly to a cloud security group, but applied at the HTTP routing level.

## 🚧 Use Case

This plugin is designed for scenarios like:

- Restricting internal services to VPN traffic
- Blocking access to sensitive routes from LAN/proxy networks
- Enforcing host-based access rules without external auth services
- Adding lightweight L7 filtering in front of services

### 🔥 Why?
In some scenarios such as *PaaS* managed environments (*Dokploy*, *Coolify*, ...), *Traefik* is not intended to be configured directly, but this plugin can be enforced an the entrypoint level, configuring the apps domains directly in the middleware

In a nutshell I developed this in order to be able to reuse the same ssl certificates generated with *Dokploy* and *Traefik*, over my VPN network, in that case I configure every service as a public service, and then add the GateKeeper middleware to the entrypoint, configuring the route with the corresponding rules. Probably it is necessary to changue the SSL certificate method to a DNS challenge instead of the default HTTP challenge, but I haven't tested it yet.


## ⚠️ Important Limitations
This is NOT a replacement for a real firewall
It relies on req.RemoteAddr (no X-Forwarded-For parsing)
Should be used behind a trusted proxy or controlled network
I am not a security expert, and it is experimental by the moment, so use at your own risk.

## ⚙️ Configuration
Static Configuration (Traefik)

If using local plugin:

```yaml title="traefik.yml"
experimental:
  plugins:
    gatekeeper:
      moduleName: github.com/caverar/traefik-mini-firewall
      version: "v0.1.0-alpha"
```

Dynamic Configuration

```yaml title="middlewares.yml"
http:
  middlewares:
    gatekeeper:
      plugin:
        gatekeeper:
          defaultPolicy:
            action: block
            destinationHosts:
              - "*"
          policies:
            vpn:
              sources:
                - "10.0.0.0/8"
              action: allow
              destinationHosts:
                - "*"
            cloudProxy:
              sources:
                - "192.168.0.0/16"
              action: block
              destinationHosts:
                - "dashboard.example.com"
```

## 🧠 Policy Model

### Evaluation Order (NOT READY)
- Policies are evaluated in declaration order
- First match wins
- If no policy matches → fallback to defaultPolicy

## 🔐 Policy Structure
### Policy
```yaml
policies:
  name:
    sources: ["CIDR", "*"]
    action: "allow" | "block"
    destinationHosts: ["host", "*.domain.com", "*"]
```

### Fields
- `sources`
    - List of CIDR ranges
    - "*" matches all IPs
- `destinationHosts`
    - Exact match: "example.com"
    - Wildcard subdomain: "*.example.com"
    - "*" matches all hosts
- `action`
    - `allow` → request continues
    - `block` → returns 403 Forbidden



## Default Policy

Acts as a catch-all:


```yaml
defaultPolicy:
  action: block
  destinationHosts:
    - "*"
```


## 🧪 Example Scenarios
### Allow only VPN access
```yaml
policies:
  vpn:
    sources:
      - "10.0.0.0/8"
    action: allow
    destinationHosts:
      - "*"
defaultPolicy:
  action: block
```
## Block internal users from admin panel
```yaml

policies:
  block-internal:
    sources:
      - "192.168.0.0/16"
    action: block
    destinationHosts:
      - "admin.example.com"
defaultPolicy:
  action: allow
  destinationHosts:
    - "*"
```

## 🔍 Matching Behavior
### IP Matching
- Uses CIDR parsing via Go net package
- Invalid CIDRs are ignored

### Host Matching
- Exact match: example.com
- Wildcard:
  - "*.example.com" matches sub.example.com
  - Does NOT match example.com

## 🧾 Logs

### Blocked requests are logged to stdout:

```sh
[GateKeeper] BLOCK: IP 192.168.1.10 matched policy 'cloudProxy' for host dashboard.example.com
```

### Unmatched requests:
```sh
[GateKeeper] DENY: No policy matched for IP 8.8.8.8 and host example.com
```

## 🧪 Testing

### Includes unit tests covering:
- CIDR matching
- Wildcard host matching
- Default policy fallback
- Allow/Block behavior

Run:
```
go test
```


## 🧱 Architecture Notes
- Middleware runs inline in Traefik request pipeline
- Uses precompiled internal policy representation for performance
- No external dependencies

## 🚀 Future Improvements (ideas)
- Support for X-Forwarded-For
- Regex host matching
- Rule priority / explicit ordering
- Metrics (Prometheus)
- Structured logging


## 📄 License
### [MIT](./LICENSE)