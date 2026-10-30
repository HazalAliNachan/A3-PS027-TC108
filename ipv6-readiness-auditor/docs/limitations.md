# Technical Limitations and Environment Caveats

**Project:** IPv6 Website and Dependency Readiness Auditor  
**Team:** First_Timers (Nachan HaazalAli Danish, Eshaan Brahmi)  
**Hackathon:** AIORI Hackathon 3 | Project ID: A3-PS027-TC108  

---

## 1. Auditor Host Network Environment

Live TCP, TLS, and HTTP IPv6 connection testing requires the machine executing the auditor to have an active default IPv6 internet route.
- If the auditor is run on an **IPv4-only ISP connection or VM** lacking an IPv6 gateway, outbound IPv6 packets cannot leave the local network interface (`OS error 10051 / ENETUNREACH`).
- **How the Auditor Handles This:**
  - The application automatically tests outbound reachability at startup.
  - If IPv6 routes are unavailable, the auditor resolves `AAAA` records over dual-stack DNS and flags live tests with a transparent notice: `Testing Environment Limitation`.
  - It **never** fabricates a connection result or concludes that a target website is broken due to local network constraints.

---

## 2. Browser Discovery Scope

- Discovered dependencies represent resources requested during the automated Playwright Chromium loading session.
- **Dynamic Assets:** Resources loaded conditionally via user interaction (e.g. clicking buttons, scrolling, logging in, or location-based scripts) might not be discovered in an initial unauthenticated page load.
- **Client Policy Blocking:** Assets blocked by browser security policies (e.g. ad blockers or CORS) are explicitly isolated and classified under `Browser Resource Loading`, rather than misattributed to network protocol failures.

---

## 3. Anycast, GeoDNS, and CDN Edge Variations

- Global websites (e.g. Wikipedia, Cloudflare, Google) use GeoDNS and Anycast routing.
- The IP addresses resolved during an audit reflect the nameserver responses from the auditor's geographic region.
- Results represent the observed network state at the recorded UTC timestamp.

---

## 4. Web Application Firewall (WAF) Rate Limiting

- Third-party CDNs or protection layers (e.g. Cloudflare Under Attack mode, Akamai Bot Manager) may issue HTTP `403 Forbidden` or `429 Too Many Requests` to automated user-agents.
- The auditor classifies HTTP 4xx responses under `HTTP Access Restriction` with medium confidence, preserving the distinction between transport-level IPv6 connectivity and application-layer access controls.
