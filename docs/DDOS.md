# Defending against denial-of-service attacks

A web application firewall can stop **application-layer** floods. It cannot stop **volumetric** attacks, and no software running
inside a cluster can: when an attacker sends more traffic than your internet link or load balancer can carry, the link is full before a
single packet reaches the WAF. Real protection therefore has two layers, and you need both.

## Layer 1: network and volumetric attacks (outside the cluster)
This must be provided by your cloud provider or a CDN, in front of A Shield WAF. Features and prices change, so check the provider's current documentation:

| Where you run | What to use |
|---|---|
| AWS | AWS Shield Standard is included for all AWS customers; put CloudFront (CDN) or a Network/Application Load Balancer in front; Shield Advanced and AWS WAF rate rules are optional paid extras |
| Azure | DDoS infrastructure protection is always on; Azure Front Door or Application Gateway in front; DDoS Network Protection is an optional paid tier |
| Google Cloud | the global external load balancer absorbs a large share of volumetric traffic; Cloud Armor is the paid extra |
| Anywhere | a CDN / DDoS-absorbing proxy with a free plan (not open source) in front of your public address, and an ISP or provider that offers null-routing / scrubbing |
| On-premises | ask your ISP for DDoS scrubbing; keep upstream capacity larger than the expected attack, and never expose the origin address once a CDN is in place |

Also: keep the origin address secret behind a CDN (restrict the load-balancer security group to the CDN's ranges), and list the
CDN/load-balancer ranges under **Settings, Real client IP**, so the real client address is used by every rule.

## Layer 2: application-layer floods (what A Shield WAF does)
| Control | Where | What it does |
|---|---|---|
| Strict timeouts and header limits | built in | slow-loris and slow-POST connections are closed after 10-15 s; oversized headers are refused |
| Per-IP connection cap | built in | one address cannot hold hundreds of connections (300 per site) |
| Rate limiting | Site settings | requests per second per address, burst allowance, HTTP 429 |
| Auto-ban | Settings | addresses that keep getting blocked or rate-limited are banned for a period |
| IP reputation feeds | Threat intel | known botnets and attacker networks are refused before any rule runs |
| Country rules | Site settings | refuse or allow whole countries |
| Anti-bot challenge | Site settings | scripts that cannot run JavaScript never reach the application |
| **Under-attack mode** | Sites page | one click: every visitor must pass the challenge and a rate limit applies |
| **Automatic escalation** | Settings, Flood defence | when a site exceeds a request-rate threshold, under-attack mode switches on by itself and off again when traffic calms down |
| Positive security model | Site settings | only the paths and content types the application really uses are accepted |

## During an attack: a short playbook
1. Open **Sites** and press **Under attack ON** for the affected site (or **all**). Real users pass the challenge once; bots stop.
2. Open **Attack log** and the dashboard: note the top addresses and countries. Ban addresses (IP bans) or add country rules.
3. Check **Threat intel**: refresh the feeds so the newest lists are loaded.
4. If the link itself is saturated (the dashboard shows few requests but users cannot connect), the attack is volumetric: contact your cloud
   provider or CDN, and enable their DDoS protection.
5. When it is over, press **Under attack OFF** (automatic episodes end by themselves) and review the audit trail.

## Capacity planning
The engine uses about 60 MB per worker plus the rule set per site. For heavy traffic raise the engine memory limit, and note that one
replica is a single point of failure (see SECURITY.md); consider a second independent instance behind DNS or a load balancer with health checks.
