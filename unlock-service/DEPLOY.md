# URLCheck unlock service: deploy (staging, workers.dev only)

Status 2026-10-22: code and tests done (`npm test`: 36/36). **NOT deployed.** The Cloudflare connector on the box
(hosting@onehundredproof.com, account 7a6c7ec6…) has no Workers/D1/Access scopes (403), and no Unite Cloudflare API
token is on the box.

## What is needed from Zack (one of)
A. Reconnect the Cloudflare connector and grant: **Workers Scripts Write**, **D1 Write**, **Account Settings Read**,
   **Access: Apps and Policies Write**, **Access: Organizations, Identity Providers and Groups Write** (for the Unite account).
B. Or put a scoped API token for the Unite Cloudflare account at a box path, e.g. `/workspace/soc/secrets/cf-urlcheck-unlock.token`
   (the same permissions as above), and say which account to use.

## Steps (wrangler; ~10 min once auth exists)
```
cd unlock-service && npm ci
npx wrangler d1 create urlcheck-unlock-staging            # copy database_id into wrangler.toml
npx wrangler d1 migrations apply urlcheck-unlock-staging --remote
openssl rand -hex 32 | npx wrangler secret put UNLOCK_PEPPER   # never echo/commit
npx wrangler deploy                                        # -> https://urlcheck-unlock-staging.<subdomain>.workers.dev
curl https://urlcheck-unlock-staging.<subdomain>.workers.dev/v1/health
```
Until `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are set, `/admin*` returns 503 (fail closed). `/v1/unlock/redeem` works
without them, but no codes can exist until /admin is enabled.

## Cloudflare Access (Unite sign-in) for /admin
1. Zero Trust > Settings > Authentication: add the **Microsoft Entra ID** IdP for the unite-networks.com tenant.
   This needs an Entra app registration: redirect URI `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback`,
   client secret, and the `email`, `openid`, `profile` scopes (plus `GroupMember.Read.All` if you restrict by Entra group).
2. Access > Applications > Self-hosted: domain `urlcheck-unlock-staging.<subdomain>.workers.dev`, path `/admin`.
   Policy **Allow**: Emails ending in `@unite-networks.com` AND (recommended) the Entra group "Unite Engineers".
   Session duration 8h. Copy the **Application Audience (AUD) tag**.
3. In wrangler.toml set `ACCESS_TEAM_DOMAIN = "<team>.cloudflareaccess.com"` and `ACCESS_AUD = "<aud>"`, then `npx wrangler deploy`.
   The Worker verifies the Access JWT itself (RS256 against the team certs, aud, iss, exp) and re-checks the email domain.
   It does not rely on the edge alone.
4. Do NOT put `/v1/unlock/redeem` behind Access. The extension calls it without user credentials. It is protected by
   ~50-bit codes, a 15-minute window, single use, a per-device (5) and per-IP (20) failure limit in 15 min, and an Origin check.

## Pilot hookup (needs Zack GO; NOT done)
Script 324, for ZACK7B4F + L-5CD2419P4Y only (same pilot list as 1.3.2):
`unlockValidationMode = geco_endpoint`, `unlockEndpointUrl = https://…/v1/unlock/redeem`, `unlockDeviceLabel = $env:COMPUTERNAME`
(managed policy strings), with extension 1.4.0 on the pilot channel.
