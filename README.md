# at-oidc

OIDC identity provider that bridges AT Protocol identity to standard OIDC
clients. Users authenticate with their ATProto handle (via any PDS), and
at-oidc issues standard OIDC id_tokens with the user's DID as the `sub` claim.

Works with any OIDC client, though built specifically for Headscale
and Tailscale SaaS.

## How It Works

```
OIDC Client (Headscale, Tailscale, etc.)
    │
    ├─ /authorize → user enters ATProto handle
    │               → at-oidc resolves handle → DID → PDS
    │               → redirects to PDS for AT Protocol OAuth
    │
    ├─ /oauth/callback ← PDS redirects back with auth code
    │               → at-oidc exchanges code, gets DID
    │               → checks whitelist (if non-empty)
    │               → issues OIDC auth code
    │
    └─ /token → client exchanges OIDC code for id_token
                → id_token contains: DID (sub), handle (preferred_username),
                  email (computed from handle)
```

## Features

- **AT Protocol OAuth** via indigo - users authenticate with any PDS
- **OIDC provider** - discovery, JWKS, authorize, token, userinfo endpoints
- **Whitelist membership control** - restrict access to specific DIDs
- **WebFinger** - gated by whitelist (only responds for known handles)
- **Multi-client config** - serve multiple OIDC clients via `clients.yaml`
- **Admin UI** - standalone whitelist management page

## Setup

### 1. Generate JWK

```bash
mkdir -p keys
./at-oidc create-jwk --out keys/jwk.key
```

### 2. Configure

Copy `.env.example` to `.env` and fill in:

```bash
ATMESH_HOSTNAME=at-oidc.example.com    # issuer hostname (no protocol prefix)
ATMESH_ADMIN_TOKEN=your-secret-token    # admin UI auth
ATMESH_SESSION_SECRET=your-secret       # signs session cookies
ATMESH_CLIENTS_FILE=/data/clients.yaml  # multi-client config
```

Configure OIDC clients in `clients.yaml`:

```yaml
clients:
  - id: headscale
    secret: your-secret
    redirect_uris:
      - https://headscale.example.com/oidc/callback
  - id: tailscale
    secret: ""
    redirect_uris:
      - https://login.tailscale.com/a/oauth_response
```

### 3. Deploy

```bash
docker compose build
docker compose up -d
```

## Limitations

- **No automatic eviction** - removing a DID from the whitelist prevents new
  auth but doesn't kick existing sessions. OIDC is authentication-only; eviction
  is app-specific (e.g., call Headscale's API to delete the node).
- **No token revocation** - issued id_tokens are valid until expiry (10 min).
- **Email length** - email is computed as `<handle>@<hostname>`. ATProto handles
  can exceed the RFC 5321 local part limit of 64 chars. Fine for typical handles,
  breaks for edge cases.
- **Single instance** - SQLite backend, no HA. If at-oidc is down, new auth fails
  until it's back. Existing sessions are unaffected.
