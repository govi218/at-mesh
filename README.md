# at-mesh

AT Protocol identity bridge for WireGuard mesh networks. Provides OIDC
authentication for Headscale, with DID-based membership control via a
whitelist.

## Headscale Connectivity (Important)

The Tailscale TS2021 noise protocol uses HTTP/1.1 `Upgrade` headers. Cloudflare
tunnels strip non-standard Upgrade values, so the control plane connection fails
when routed through Cloudflare.

Headscale must be exposed via **Caddy** (not Cloudflare Tunnel) so Upgrade
headers pass through:

1. DNS A record for `headscale.glados.computer` → home router public IP
   (DNS-only, NOT proxied through Cloudflare)
2. Router port-forwards WAN 443 → `192.168.18.35:443`
3. Caddy handles TLS (ACME) + reverse proxy to Headscale (`:8081`)

at-mesh itself can stay behind Cloudflare (OIDC flow is plain HTTP, no Upgrade
headers needed). Only the Headscale control plane requires the Caddy path.

## Acknowledgments

The admin UI in `ui/` is derived from
[headscale-ui](https://github.com/gurucomputing/headscale-ui) by gurucomputing,
licensed under the BSD 3-Clause License. See `ui/LICENSE.md` for the full
license text.
