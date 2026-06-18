#!/bin/bash
# Local smoke test for at-mesh OIDC flow
# Usage: ./scripts/test-local.sh

set -euo pipefail

BASE="http://localhost:9090"
CLIENT_ID="headscale"
CLIENT_SECRET="secret123"
REDIRECT_URI="http://localhost:9999/callback"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }

# Check at-mesh is running
info "Checking at-mesh is running..."
curl -sf "$BASE/health" > /dev/null 2>&1 || fail "at-mesh not running at $BASE. Start it first."
pass "at-mesh is running"

# 1. Discovery
info "Testing discovery..."
DISCOVERY=$(curl -sf "$BASE/.well-known/openid-configuration")
echo "$DISCOVERY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['issuer'] == 'https://mesh.glados.computer', f'wrong issuer: {d[\"issuer\"]}'
assert '/authorize' in d['authorization_endpoint'], 'no authorize endpoint'
assert '/token' in d['token_endpoint'], 'no token endpoint'
assert '/jwks.json' in d['jwks_uri'], 'no jwks_uri'
print('  issuer:', d['issuer'])
print('  authorize:', d['authorization_endpoint'])
print('  token:', d['token_endpoint'])
" || fail "discovery failed"
pass "discovery"

# 2. JWKS
info "Testing JWKS..."
JWKS=$(curl -sf "$BASE/.well-known/jwks.json")
echo "$JWKS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert len(d['keys']) == 1, 'no keys'
k = d['keys'][0]
assert k['alg'] == 'ES256', f'wrong alg: {k[\"alg\"]}'
assert k['kty'] == 'EC', f'wrong kty: {k[\"kty\"]}'
assert 'kid' in k, 'no kid'
print('  alg:', k['alg'], 'kid:', k['kid'])
" || fail "JWKS failed"
pass "JWKS"

# 3. WebFinger
info "Testing WebFinger..."
WF=$(curl -sf "$BASE/.well-known/webfinger?resource=acct:admin@mesh.glados.computer")
echo "$WF" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['subject'] == 'acct:admin@mesh.glados.computer', f'wrong subject: {d[\"subject\"]}'
assert d['links'][0]['href'] == 'https://mesh.glados.computer', 'wrong issuer'
print('  subject:', d['subject'])
print('  issuer:', d['links'][0]['href'])
" || fail "WebFinger failed"
pass "WebFinger"

# 4. Authorize — valid client
info "Testing authorize (valid client)..."
AUTH_RESP=$(curl -sf -o /dev/null -w '%{http_code} %{redirect_url}' \
  "$BASE/authorize?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&response_type=code&scope=openid+profile+email&state=test123")
HTTP_CODE=$(echo "$AUTH_RESP" | cut -d' ' -f1)
REDIRECT_URL=$(echo "$AUTH_RESP" | cut -d' ' -f2-)

[ "$HTTP_CODE" = "303" ] || fail "authorize returned $HTTP_CODE, expected 303"
[[ "$REDIRECT_URL" == *"$REDIRECT_URI"* ]] || fail "redirect to wrong URL: $REDIRECT_URL"
[[ "$REDIRECT_URL" == *"code="* ]] || fail "no code in redirect"
[[ "$REDIRECT_URL" == *"state=test123"* ]] || fail "state not preserved"

CODE=$(echo "$REDIRECT_URL" | sed 's/.*code=//' | sed 's/&.*//')
pass "authorize (valid client, code=$CODE)"

# 5. Authorize — unknown client
info "Testing authorize (unknown client)..."
BAD_CLIENT=$(curl -s "$BASE/authorize?client_id=evil&redirect_uri=$REDIRECT_URI&response_type=code&scope=openid")
echo "$BAD_CLIENT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['error'] == 'invalid_client', f'expected invalid_client, got: {d[\"error\"]}'
" || fail "unknown client should be rejected"
pass "authorize rejects unknown client"

# 6. Authorize — bad redirect_uri
info "Testing authorize (bad redirect_uri)..."
BAD_REDIRECT=$(curl -s "$BASE/authorize?client_id=$CLIENT_ID&redirect_uri=https://evil.com/steal&response_type=code&scope=openid")
echo "$BAD_REDIRECT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'redirect_uri' in d.get('error_description', ''), f'expected redirect_uri error, got: {d}'
" || fail "bad redirect_uri should be rejected"
pass "authorize rejects unregistered redirect_uri"

# 7. Token exchange — valid
info "Testing token exchange (valid)..."
TOKEN_RESP=$(curl -sf -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&redirect_uri=$REDIRECT_URI")
echo "$TOKEN_RESP" | python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
assert 'id_token' in d, 'no id_token'
assert d['token_type'] == 'Bearer', f'wrong token_type: {d[\"token_type\"]}'

# Decode the id_token payload (without verifying signature)
parts = d['id_token'].split('.')
payload = base64.urlsafe_b64decode(parts[1] + '==')
claims = json.loads(payload)
assert claims['iss'] == 'https://mesh.glados.computer', f'wrong issuer: {claims[\"iss\"]}'
assert claims['sub'] == 'did:plc:placeholder', f'wrong sub: {claims[\"sub\"]}'
assert claims['aud'] == ['headscale'], f'wrong audience: {claims[\"aud\"]}'
print('  sub:', claims['sub'])
print('  iss:', claims['iss'])
print('  aud:', claims['aud'])
print('  exp:', claims['exp'])
" || fail "token exchange failed"
pass "token exchange"

# 8. Token exchange — wrong secret
info "Testing token exchange (wrong secret)..."
# Get a fresh code first
FRESH_RESP=$(curl -sf -o /dev/null -w '%{redirect_url}' \
  "$BASE/authorize?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&response_type=code&scope=openid&state=test2")
FRESH_CODE=$(echo "$FRESH_RESP" | sed 's/.*code=//')

BAD_SECRET=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$FRESH_CODE&client_id=$CLIENT_ID&client_secret=wrong&redirect_uri=$REDIRECT_URI")
echo "$BAD_SECRET" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['error'] == 'invalid_client', f'expected invalid_client, got: {d[\"error\"]}'
" || fail "wrong secret should be rejected"
pass "token exchange rejects wrong secret"

# 9. Token exchange — code reuse (one-time use)
info "Testing token exchange (code reuse)..."
REUSE=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&redirect_uri=$REDIRECT_URI")
echo "$REUSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['error'] == 'invalid_grant', f'expected invalid_grant, got: {d[\"error\"]}'
" || fail "code reuse should be rejected"
pass "token exchange rejects code reuse"

# 10. Userinfo
info "Testing userinfo..."
USERINFO=$(curl -sf -H "Authorization: Bearer test-token" "$BASE/userinfo")
echo "$USERINFO" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'sub' in d, 'no sub in userinfo'
print('  sub:', d['sub'])
" || fail "userinfo failed"
pass "userinfo"

echo ""
echo -e "${GREEN}All tests passed!${NC}"
