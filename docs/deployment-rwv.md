# tang.rwv.dev deployment

This fork deploys Tang to Cloudflare Workers using an immutable Worker Secret,
with private key backups in 1Password and manual rotation from a local machine.
The upstream KV entry point remains available for other deployments.

## Deployment record

Deployed on 2026-11-02 to <https://tang.rwv.dev> using local Wrangler 4.110.0.
Source commit: `becabfd1b5fba74815d3766d02e8da4536a70a44`.
Worker version: `cae9e9a9-de2b-4a79-ab1e-bc5138d65417`.
The initial signing/exchange key pair was backed up to the Personal 1Password
vault and read back successfully before deployment. No private values or backup
item identifiers are recorded in this public repository.

Live verification passed: health endpoint, independent Web Crypto ES512
verification, blinded ECMR recovery, and `/rotate` returning 404. Cloudflare
settings confirm a single `secret_text` binding named `TANG_KEYSET`, no KV
binding, no Cron schedules, and disabled workers.dev/preview hostnames.
Retired-key compatibility passed in the local Workers runtime. A real clevis
client round trip is still required before binding production disks.

## Configuration

- Entry point: `src/worker-secrets.ts`
- Wrangler configuration: `wrangler.secrets.jsonc`
- Worker: `tang-edge`; custom domain: `tang.rwv.dev`
- Required secret: `TANG_KEYSET`
- No KV namespace, scheduled rotation, or `ROTATE_TOKEN` is required.
- `/adv`, `/adv/:thumbprint`, and `/rec/:thumbprint` remain standard Tang routes.
- `/rotate` is not mounted. The deployment has no scheduled handler or Cron.
- The workers.dev hostname and preview URLs are disabled.

`TANG_KEYSET` contains `{ "version": 1, "active": [...], "retired": [...] }`.
Both arrays contain private P-521 JWKs. Active keys are advertised; retired keys
remain available for old clients' recovery and signature requests. Secret values
must never be committed, printed, placed in Wrangler vars, or passed as CLI arguments.

## First deployment

Install dependencies with `bun install --frozen-lockfile`. Use the existing local
Wrangler rather than `bun run deploy`, which resolves the project dependency.
Log in to Cloudflare and unlock the 1Password desktop app with CLI integration enabled.

```sh
export WRANGLER_BIN="$(command -v wrangler)"
export TANG_VAULT=Personal
"$WRANGLER_BIN" whoami
bun test
./node_modules/.bin/tsc -p tsconfig.ci.json
bun run scripts/cloudflare-secrets.ts init
bun run scripts/cloudflare-secrets.ts dry-run
bun run scripts/cloudflare-secrets.ts deploy
bun run scripts/verify-cloudflare.ts
```

`init` generates a signing/exchange pair and creates a versioned API Credential
item in 1Password. It reads the concealed field back and compares the complete
key set before writing `.tang-cloudflare-state.json`. This local ignored file
contains only the backup item ID, vault, timestamp, and public thumbprints.
`init` refuses to replace existing state. Deployment always retrieves the
verified key set from that backup.

The script writes the secret into a private temporary directory, deploys code
and secret together using `wrangler deploy --secrets-file`, then removes the
temporary data and logs even if deployment fails. Only deployment metadata is
printed. No Cloudflare API token is injected into the Worker; local Wrangler
OAuth credentials authorize deployment.

## Manual rotation

```sh
export WRANGLER_BIN="$(command -v wrangler)"
bun run scripts/cloudflare-secrets.ts status
curl --fail https://tang.rwv.dev/adv > /tmp/tang-previous-advertisement.json
bun run scripts/cloudflare-secrets.ts rotate
bun run scripts/cloudflare-secrets.ts dry-run
bun run scripts/cloudflare-secrets.ts deploy
bun run scripts/verify-cloudflare.ts https://tang.rwv.dev /tmp/tang-previous-advertisement.json
```

Rotation creates a new pair, moves all previous active keys into `retired`,
retains every existing retired key, and saves a NEW 1Password snapshot before
deployment. Earlier backup items are not modified. A backup may represent a
pending generation until deployment succeeds; retry `deploy` after a failure.

After deployment, verify the advertisement with an independent ES512 verifier,
test a fresh clevis encryption/decryption round trip, and confirm that clients
bound before rotation can still recover. Only then migrate clients to the new
advertisement. Keep a separate working LUKS recovery passphrase.

Do not delete an old exchange key merely because a scheduled interval elapsed.
It remains required by disks bound to that key until those clients are migrated.
The helper deliberately never prunes keys. It refuses a key set above 5,000 bytes
to leave room below Cloudflare's 5 KB per-secret limit. If it reaches that limit,
extend storage to multiple secret bindings before performing another rotation;
do not remove required old keys to make room.

## Recovery

If the local state file is lost, find the latest successfully deployed
`Tang-Edge / Cloudflare / <timestamp>` item in the chosen 1Password vault and
restore `.tang-cloudflare-state.json` with this non-secret structure:

```json
{
  "itemId": "<1Password item ID>",
  "vault": "Personal",
  "createdAt": "<timestamp>",
  "thumbprints": ["<signing thumbprint>", "<exchange thumbprint>"]
}
```

Run `status`, then `deploy`. Do not run `init` to recover a service that has bound
clients: generating unrelated keys cannot recover the old bindings. When rolling
back code, preserve the newest complete key set; reverting to an older secret
snapshot can break clients that already used newer keys.

## Changes from upstream

Upstream base: `281508fe27a0bbe5c2976763134dcb55fa6e21f8`.

1. Fixed ES512 double hashing: noble-curves v2 expects the unhashed signing input.
   Added an independent Web Crypto verification regression test.
2. Extracted the shared protocol app, preserving the original KV deployment and
   adding a separate Worker Secrets entry point without management mutation routes.
3. Added immutable secret storage, validation, duplicate rejection, and failure
   responses that do not disclose secret contents.
4. Added a dedicated Cloudflare config and generated binding types; pinned the
   custom domain and disabled alternative public deployment hostnames.
5. Added backup-first provisioning/deployment/manual rotation tooling, plus tests
   for current and retired key recovery, advertisements, and disabled rotation.

The upstream `setup.sh` is intentionally bypassed for this deployment. At the base
commit it uses macOS-incompatible `grep -P` and `sed -i`, looks for KV placeholders
that differ from `wrangler.toml`, leaves the domain placeholder unresolved, and
mixes global Wrangler setup with project-local Wrangler deployment. The WAF
example `^/(adv|rec/|rotate)?$` also rejects required `/adv/:thumbprint` and
`/rec/:thumbprint` paths. Do not copy that rule.

References: [Tang rotation](https://github.com/latchset/tang#key-rotation),
[Worker Secrets](https://developers.cloudflare.com/workers/configuration/secrets/),
[limits](https://developers.cloudflare.com/workers/platform/limits/#environment-variables),
[noble prehashed signing](https://github.com/paulmillr/noble-curves#prehashed-signing).
