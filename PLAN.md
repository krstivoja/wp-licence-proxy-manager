---
title: "Agency License Vault: Build Plan"
slug: agency-license-vault-plan
status: planning
---

# Agency License Vault: Build Plan

Build plan for Claude Code. Read `OVERVIEW` (in the mk-wiki vault) for the why,
and the `plugin-starter-kit` and `wp-rules-php` notes there for file layout and
code style, before starting any phase.

## 1. Goal and non-goals

**Goal.** An agency stores its real vendor license keys (Bricks, Oxygen, later
others) on its own server. Client sites never hold the real key, so someone with
a client's database or files cannot copy it. License and update requests from
client sites are relayed through the agency server, which inserts the real key.

**Hard rules (non-negotiable, also in CLAUDE.md):**
- Each masked license works only on the one URL (plus explicit aliases) the
  agency registered for it. The URL is set and changed only by the agency. See 4.8.
- The vendor always receives the **real key** and the **client's real domain /
  site URL**. The relay never rewrites site identity, never answers a license
  check itself, and never fabricates a vendor response.
- Vendor responses are passed back unchanged, except that any echoed real key is
  masked.
- Never edit vendor plugin or theme files. Change what the builder *receives*
  (HTTP filters, options), never what it *is*.
- The relay forwards only to an allowlist of vendor hosts. It is never an open proxy.
- Real keys never appear in logs, responses to clients, error messages, or the
  client database.

**Non-goals:** multi-tenant SaaS, reselling licenses, bypassing seat limits,
supporting vendors whose checks cannot be relayed faithfully.

## 2. Gates before code

### Gate A: vendor terms (manual, Marko)
Email Bricks and Oxygen: agency tier, N client sites, key stored on agency
server, license and update requests relayed with the real client domain. Record
answers in `DECISIONS.md`. **Do not build an adapter for a vendor without a
written yes.**

### Gate B: discovery spike (Claude Code, Phase 0)
Find out exactly how each builder validates and updates. Results decide whether
the design works for that vendor.

## 3. Repository layout

Monorepo with two deliverables:

```
wp-licence-proxy-manager/
├── CLAUDE.md
├── PLAN.md
├── DECISIONS.md
├── GOTCHAS.md
├── tools/
│   └── alv-sniffer/               # Phase 0 throwaway diagnostic mu-plugin
│       ├── alv-sniffer.php
│       └── README.md
├── docs/
│   └── vendor-profiles/
│       ├── bricks.md              # filled in during Phase 0
│       └── oxygen.md              # filled in during Phase 0
├── vault/                         # Plugin on the agency server (Phase 1+)
│   ├── agency-license-vault.php
│   ├── composer.json              # PSR-4 DPlugins\LicenseVault\ → App/
│   ├── App/
│   │   ├── App.php
│   │   ├── Crypto/KeyCipher.php           # libsodium secretbox
│   │   ├── Database/Schema.php            # custom tables + migrations
│   │   ├── Database/Repositories/         # License, Site, Assignment, Log
│   │   ├── Relay/RelayController.php      # REST: /relay, /package
│   │   ├── Relay/RequestSigner.php        # HMAC verify (shared algorithm)
│   │   ├── Relay/ReplayGuard.php
│   │   ├── Relay/RateLimiter.php
│   │   ├── Support/DomainNormalizer.php   # shared with connector
│   │   ├── Vendors/VendorAdapter.php      # interface
│   │   ├── Vendors/BricksAdapter.php
│   │   ├── Vendors/OxygenAdapter.php
│   │   ├── Admin/                         # screens, list tables
│   │   ├── Alerts/AlertService.php        # Phase 5
│   │   └── Cron/RenewalAlerts.php
│   └── tests/
└── connector/                     # mu-plugin on each client site (Phase 3+)
    ├── alv-connector.php          # single-file loader
    ├── alv-connector/
    │   ├── Connector.php
    │   ├── HttpInterceptor.php            # pre_http_request
    │   ├── RequestSigner.php              # HMAC sign (same algorithm)
    │   ├── DomainNormalizer.php           # shared copy
    │   ├── PlaceholderManager.php         # writes placeholder into builder option
    │   ├── ScreenGuard.php                # hides license screens
    │   └── GraceCache.php
    └── tests/
```

Namespace `DPlugins\LicenseVault` (vault) and `DPlugins\LicenseVault\Connector`
(connector). PHP 7.4+, WP 6.2+.

## 4. Core design

### 4.1 Key storage
- `KeyCipher` uses `sodium_crypto_secretbox` with a 32-byte key from the
  `ALV_ENCRYPTION_KEY` constant (base64) in `wp-config.php`. Refuse to boot the
  vault (admin notice) if it is missing.
- Each ciphertext stores its own nonce. Include a key version byte so the
  encryption key can be rotated later.
- Decrypt only inside the relay request, then `sodium_memzero` the plaintext.

### 4.2 Site authentication
- Registering a site requires the agency to enter its canonical URL, then creates
  `site_id` (public, UUID) and `site_secret` (32 random bytes). The secret is
  shown **once** with a ready `wp-config.php` snippet defining `ALV_SITE_ID`,
  `ALV_SITE_SECRET`, `ALV_SITE_URL` and `ALV_VAULT_URL`.
- The vault stores `site_secret` **encrypted** (it needs the plaintext to verify
  HMACs).
- Every relayed call carries headers: `X-ALV-Site`, `X-ALV-Site-URL`,
  `X-ALV-Timestamp`, `X-ALV-Nonce`, `X-ALV-Signature`.
- Signature: `HMAC-SHA256(secret, method \n target_url \n site_url \n timestamp
  \n nonce \n sha256(body))`. Including `site_url` in the signature means it
  can't be altered in transit.
- `ReplayGuard`: reject timestamps outside ±300 s and nonces seen within that
  window (stored as transients or in a small table).
- Domain binding rules are in 4.8.

### 4.3 Placeholder and key substitution
- Placeholder format: `ALV-MASKED-{site_id}`. The connector writes it into the
  builder's license option so the builder thinks a key is set and sends it in its
  requests.
- The relay (via the vendor adapter) replaces the placeholder with the real key
  in query string, form body or JSON body, **and nothing else**.
- Before forwarding, the adapter verifies the site URL in the request matches the
  registered domain for `site_id`. Mismatch → 403.
- On the way back, the adapter replaces any occurrence of the real key in the
  response body and headers with the placeholder.

### 4.4 Vendor adapter interface

```php
interface VendorAdapter {
    public function slug(): string;                         // 'bricks'
    public function hosts(): array;                          // allowlisted hosts
    public function licenseOptionName(): ?string;            // where builder stores key
    public function matches(string $url): bool;              // is this a license/update call
    public function extractSiteUrl(array $request): ?string; // domain the vendor will see
    public function substituteKey(array $request, string $placeholder, string $realKey): array;
    public function maskResponse(array $response, string $realKey, string $placeholder): array;
    public function isPackageDownload(string $url): bool;
}
```

Adapters are filled in from the Phase 0 findings. No adapter is registered
without Gate A.

### 4.5 Data model (custom tables, prefix `{$wpdb->prefix}alv_`)

| Table | Columns |
|---|---|
| `licenses` | id, vendor, label, key_cipher, key_last4, seats_total, tier, renews_at, notes, created_at, updated_at |
| `sites` | id, site_uuid, label, client_name, domain (canonical, normalized), domain_aliases (JSON list), secret_cipher, status (active/suspect/revoked), known_ips (JSON), last_ip, last_home_url, last_seen_at, created_at |
| `assignments` | id, license_id, site_id, activated_at, revoked_at |
| `logs` | id, site_id, vendor, host, path, method, status_code, duration_ms, error, attempted_url, remote_ip, created_at |
| `domain_changes` | id, site_id, old_domain, new_domain, changed_by (user id), created_at |
| `alerts` | id, site_id, signal, severity, attempted_url, remote_ip, details (JSON, no key material), status (open/ok/revoked), resolved_by, created_at, resolved_at |

Logs store path only, never query strings or bodies. `attempted_url` is filled
only on domain-mismatch rejections. Retention: 90 days via cron.

### 4.6 REST endpoints (namespace `alv/v1`)

| Route | Auth | Purpose |
|---|---|---|
| `POST /relay` | HMAC | Forward one vendor request, return `{status, headers, body}` |
| `GET /package` | HMAC | Stream a vendor package download (Phase 4) |
| `GET /health` | HMAC | Connector heartbeat; updates `last_seen_at` |
| `POST /sites` | `manage_options` + nonce | Register site, return secret once |
| `POST /sites/{id}/revoke` | `manage_options` + nonce | Revoke site, end assignment |
| `GET /licenses/{id}/seats` | `manage_options` | Seats used/remaining |

### 4.7 Connector behaviour
- Boot only if `ALV_SITE_ID`, `ALV_SITE_SECRET`, `ALV_SITE_URL`, `ALV_VAULT_URL`
  are defined. Otherwise do nothing and show one admin notice to agency admins.
- Also requires `ALV_SITE_URL`. If `home_url()` doesn't normalize to the same
  value, the connector stops relaying, restores nothing, and shows agency admins
  a "site URL doesn't match the licensed URL" notice. A cloned or migrated copy
  therefore fails locally before any call reaches the vault.
- `HttpInterceptor` hooks `pre_http_request`. For URLs matching an allowlisted
  vendor host, it wraps the original request (method, URL, headers, body) as
  JSON, signs it, sends it to `/relay` with `wp_remote_post`, and returns the
  unwrapped vendor response to the builder. All other requests pass untouched.
- Guard against recursion: skip interception for requests to `ALV_VAULT_URL`.
- `PlaceholderManager` sets the builder's license option to the placeholder on
  activation and re-asserts it if changed.
- `ScreenGuard` removes or redirects the builder's license and settings screens
  for users without the `alv_agency` capability, and masks the key field if it
  renders anywhere.
- `GraceCache` stores the last successful vendor response per endpoint for 72 h.
  If the vault is unreachable, return the cached response and log a warning.

### 4.8 Domain binding (one masked license = one URL)

Every masked license is locked to the URL the agency registers for it. The
agency owns that URL; the client can't change it.

- **Agency-managed URL.** When registering a site, the agency enters its
  canonical URL (e.g. `https://client.se`). Stored in `sites.domain`, the only
  source of truth. Changing it is agency-only (admin or `wp alv site
  set-domain`), and is logged.
- **Optional aliases.** A short, agency-managed list in `sites.domain_aliases`
  for `www`/non-`www` or a staging URL. Each alias is explicit; no wildcards.
- **Normalization.** Lowercase host, scheme, `www.` handling and trailing slash
  normalized in one shared `DomainNormalizer` used by both vault and connector.
- **Three checks on every relayed call**, all must pass or the vault returns 403
  and nothing reaches the vendor:
  1. The signed `X-ALV-Site-URL` header matches the registered URL or an alias.
  2. The site URL inside the vendor request (via `extractSiteUrl`) matches the same.
  3. The site is `active` and has an active assignment to that license.
- **Hardcoded on the client too.** The connector reads `ALV_SITE_URL` and
  refuses to relay if `home_url()` doesn't match, so a clone fails locally first.
  Convenience check only; the vault check enforces it.
- **One placeholder, one site.** The placeholder and secret belong to exactly one
  site record. Copying them elsewhere gets nothing: requests carry a different URL
  and are rejected; a forged URL would only activate the license for the original
  domain at the vendor.
- **Misuse handling.** See 4.9 for alert severities (supersedes the earlier
  "three mismatches" rule).
- **Site moves.** Moving a client = agency updates the URL (or adds the new one
  as an alias during migration, then removes the old). No client-side action.

### 4.9 Theft detection and alerts

Goal: the agency knows quickly when anyone tries to use a masked license, a site
secret, or the real key anywhere other than the registered site.

#### What gets detected

| Signal | Where it's caught | Severity |
|---|---|---|
| Valid site ID but bad signature (has the ID, not the secret) | Vault relay | Medium, alert after 3 in 1 h |
| Valid signature but site URL ≠ registered URL (secret copied elsewhere) | Vault relay | **High, immediate**, mark `suspect` |
| Site URL inside the vendor request doesn't match (forged/tampered) | Vault relay | **High, immediate** |
| Same site calling from a new server IP or new `home_url()` | Vault relay, heartbeat | Medium, once per new IP/URL |
| Placeholder changed, removed, or replaced in the builder's field | Connector → vault | Medium, immediate |
| Connector deleted/disabled while builder active (heartbeat stops) | Vault cron | Low, after 7 days silence |
| Vendor account shows activations for unknown domains | Vendor reconciliation | **High, immediate** |

The **unapproved-URL attempt** (row 2/3) is the primary signal Marko asked for:
any attempt to use the license from a site URL that isn't approved is caught at
the relay, blocked before it reaches the vendor, and alerts immediately with the
attempted URL, IP and time.

#### Vendor reconciliation
The relay only sees requests that go through it. If the real key leaks another
way, activations happen directly at the vendor.
- If the vendor offers an account API listing activated domains, a daily cron
  (`ActivationReconciler`) compares it with registered sites and alerts on
  unknown domains. Phase 0 checks whether Bricks/Oxygen offer this.
- If not, the dashboard shows a weekly "check vendor activations" reminder with
  the domains that should be active, for a manual compare.

#### What can't be detected (document in GOTCHAS.md)
- Someone typing the placeholder directly into a builder on another site without
  the connector: the request goes straight to the vendor, which rejects it as an
  invalid key, so the vault never sees it. No harm, but no alert either.
- Theft from the vault server itself. Keep the vault on agency hosting with 2FA
  for all admins, the encryption key outside the DB, and offsite encrypted backups.

#### Alert delivery
- Channels: email to agency admins (default), plus optional Slack / generic
  webhook URL in vault settings.
- Each alert includes: site label and client, registered URL, attempted URL, IP,
  time, signal type, and one-click **Mark as OK**, **Revoke site**, **Revoke and
  reissue secret**.
- Deduplicate: same signal + site + attempted URL alerts at most once per hour;
  the dashboard still counts every event.
- Optional auto-response (off by default): on a High signal, suspend the site's
  relay access until an admin reviews it.

## 5. Phases

Each phase ends with passing tests and an updated `GOTCHAS.md` / `DECISIONS.md`.
Stop and report if a phase's acceptance criteria can't be met.

### Phase 0: Discovery spike  ← CURRENT
- `tools/alv-sniffer/alv-sniffer.php`: a throwaway mu-plugin that logs every
  `pre_http_request` and `http_api_debug` call (URL, method, header names, body
  keys — never values) to a file outside the web root.
- On a test site: activate Bricks, enter a test key, trigger license activation,
  deactivation, update check and package download. Repeat for Oxygen.
- Also check the browser devtools network tab for license calls made from JS.
- **Output:** `docs/vendor-profiles/bricks.md` and `oxygen.md`: hosts, endpoints,
  where the key and site URL appear, whether calls go through the WP HTTP API,
  how packages are downloaded, option names used, and whether an account API
  lists activated domains.
- **Acceptance:** each profile ends with a verdict: *relayable*, *partially
  relayable* (explain), or *not relayable*. Not relayable → no adapter.

### Phase 1: Vault foundation
- Scaffold `vault/`.
- `Schema` with versioned migrations (`alv_db_version` option).
- `KeyCipher` + tests (round-trip, wrong key fails, tampered ciphertext fails,
  missing constant blocks boot).
- Repositories with `$wpdb->prepare()` everywhere.
- Admin screens: Licenses (add/edit; show only `key_last4` after save), Sites
  (register → shows secret once with copy button and a `wp-config.php` snippet),
  Assignments.
- Domain binding admin: canonical URL required on registration, alias list
  editor, "change URL" action writing to `domain_changes`, shared
  `DomainNormalizer`.
- **Acceptance:** licenses and sites can be created, assigned and revoked; DB
  contains no plaintext key or secret; a site can't be saved without a URL; URL
  changes are recorded with the user; aliases are exact, never wildcards.

### Phase 2: Relay endpoint
- `RequestSigner`, `ReplayGuard`, `RateLimiter` (default 60 req/min per site),
  `DomainNormalizer` with tests.
- `RelayController::relay`: verify signature → load site (must be active) → check
  `X-ALV-Site-URL` against registered domain/aliases → find assignment and
  license → pick adapter by host (403 if none) → check the site URL inside the
  vendor request against the same → decrypt key → substitute → `wp_remote_request`
  → mask response → log → return.
- Mismatch handling: log attempted URL and IP; raise the 4.9 alerts.
- Adapter unit tests with recorded fixtures from Phase 0 (fixtures use fake keys).
- **Acceptance:** tests cover bad signature, stale timestamp, replayed nonce,
  revoked site, unknown host, header URL mismatch, body URL mismatch, alias
  accepted, `www`/trailing-slash normalization, suspect threshold, happy path. A
  test copies one site's placeholder and secret to a second domain and confirms
  every request is rejected and a High alert fires. No test output or log line
  contains the real key.

### Phase 3: Connector
- Scaffold `connector/` as a single-file mu-plugin loader with a subfolder.
- `HttpInterceptor`, `PlaceholderManager`, `ScreenGuard`, `GraceCache`, daily
  heartbeat.
- **Acceptance (test site with Bricks):** activation succeeds via the vault; the
  client DB contains only the placeholder (verify with `wp option get` and a DB
  grep for the real key); a non-agency admin can't see the license screen;
  stopping the vault still serves from the grace cache.

### Phase 4: Package downloads
- Connector rewrites allowlisted package URLs to `/package` (via
  `upgrader_pre_download` or HTTP interception, per Phase 0 findings).
- Vault streams the package from the vendor with the real key; max size limit;
  checksum pass-through if the vendor provides one.
- **Acceptance:** a builder update installs on the test site through the vault.

### Phase 5: Agency dashboard
- Overview: per license seats used/total, sites per license, last seen per site,
  recent errors.
- `RenewalAlerts` cron: email 30 / 7 / 1 days before `renews_at`, and when seats
  used ≥ 90 %. Alert when a site hasn't been seen in 7 days.
- Theft detection (4.9): `AlertService` with severity rules and deduplication,
  email + webhook channels, alert inbox with Mark as OK / Revoke / Reissue,
  new-IP/new-URL tracking, placeholder tamper reports, optional auto-suspend.
- `ActivationReconciler` cron if Phase 0 found a vendor account API; else the
  weekly manual-check reminder.
- **Acceptance:** dashboard reflects state accurately; renewal alerts fire with a
  mocked date; each 4.9 signal produces the right severity, one deduplicated
  alert, correct links, and no key material in the alert body.

### Phase 6: Hardening and release
- Encryption key rotation command: `wp alv rotate-key`.
- WP-CLI: `wp alv site register|revoke|list`, `wp alv license list`.
- Security review: capability checks on every admin action, nonces, escaping, no
  key in any output path (grep test).
- **Acceptance:** PHPStan clean at project level; ship checklist done.

## 6. Testing setup
- PHPUnit with `wp-env` or the existing gate site.
- Test vendor keys live in `~/.coding-buddy/secrets.json` (mode 600), never in
  the repo.
- A "no key leak" test: run the full relay flow, then grep logs, DB dump and
  responses for the real key; any hit fails the build.

## 7. Kickoff prompt for Claude Code

> Read `CLAUDE.md` and `PLAN.md`. We are starting Phase 0 only. The
> `tools/alv-sniffer/` mu-plugin is already scaffolded — review it, then tell me
> the exact steps to install it on the test site and capture the Bricks and
> Oxygen license traffic. Do not start Phase 1.

## 8. Open questions
- Vendor terms for Bricks and Oxygen (Gate A).
- Does either builder validate from the browser or with its own cURL? (Phase 0)
- Does Bricks or Oxygen offer an account API listing activated domains? (Phase 0)
- Admin UI: plain WP list tables for v1, or React like FanCoolo? Default: list
  tables, revisit in Phase 5.
- Product decision: internal agency tool only, or a DPlugins product later?
