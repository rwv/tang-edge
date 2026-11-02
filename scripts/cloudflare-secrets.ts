// SPDX-License-Identifier: GPL-3.0-only
// Run with Bun. Secret values are carried over stdin or a private temporary file.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateSigningKey, generateExchangeKey } from "../src/crypto/keygen";
import { p521 } from "@noble/curves/nist.js";
import { jwkThumbprint, base64urlDecode, bigintToBase64url } from "../src/crypto/jwk-utils";
import { parseKeySet, WorkerSecretStorage, type SecretKeySet } from "../src/storage/adapters/worker-secret";

const root = resolve(import.meta.dir, "..");
const statePath = join(root, ".tang-cloudflare-state.json");
const configPath = join(root, "wrangler.secrets.jsonc");
const vault = process.env.TANG_VAULT ?? "Personal";
const wrangler = process.env.WRANGLER_BIN ?? "wrangler";
interface State { itemId: string; vault: string; createdAt: string; thumbprints: string[] }

function command(program: string, args: string[], input?: string, extraEnv: Record<string,string> = {}): string {
  const result = spawnSync(program, args, {
    cwd: root, input, encoding: "utf8", maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", ...extraEnv },
  });
  // Only emit sanitized diagnostics: credential command output can contain secret data.
  if (result.error || result.status !== 0) {
    const detail = (result.stderr ?? "").replace(/[A-Za-z0-9_-]{64,}/g, "[REDACTED]").slice(0, 1200);
    throw new Error(`${program} ${args[0]} failed (exit ${result.status}): ${detail}`);
  }
  return result.stdout;
}

function readState(): State {
  if (!existsSync(statePath)) throw new Error("No local state. Run init, or restore state using the documented 1Password item ID.");
  const state = JSON.parse(readFileSync(statePath, "utf8")) as State;
  if (!state.itemId || !state.vault) throw new Error("Invalid local state");
  return state;
}

function readBackup(state: State): SecretKeySet {
  const item = JSON.parse(command("op", ["item", "get", state.itemId, "--vault", state.vault, "--format", "json", "--reveal"]));
  const value = item.fields?.find((field: {id:string}) => field.id === "credential")?.value;
  if (typeof value !== "string") throw new Error("Key set missing from 1Password backup");
  return parseKeySet(value);
}

async function validateForDeployment(set: SecretKeySet) {
  await WorkerSecretStorage.create(JSON.stringify(set));
  for (const key of [...set.active, ...set.retired]) {
    const derived = p521.Point.fromBytes(p521.getPublicKey(base64urlDecode(key.d))).toAffine();
    if (bigintToBase64url(derived.x) !== key.x || bigintToBase64url(derived.y) !== key.y) {
      throw new Error("Tang private key does not match its public coordinates");
    }
  }
}

async function saveBackup(set: SecretKeySet): Promise<State> {
  const value = JSON.stringify(set);
  // Leave a little headroom below the 5 KB per-secret limit. Never discard old keys to fit.
  if (Buffer.byteLength(value) > 5000) throw new Error("Key set exceeds one Worker Secret. Split secret storage before rotating; retain all old keys.");
  await validateForDeployment(set);
  const createdAt = new Date().toISOString();
  const thumbprints = await Promise.all(set.active.map(key => jwkThumbprint(key)));
  const template = {
    title: `Tang-Edge / Cloudflare / ${createdAt}`,
    category: "API_CREDENTIAL",
    urls: [{ href: "https://tang.rwv.dev", primary: true }],
    tags: ["tang-edge", "cloudflare", "key-backup"],
    fields: [
      { id: "credential", label: "Tang key set (TANG_KEYSET)", type: "CONCEALED", value },
      { id: "hostname", label: "hostname", type: "STRING", value: "tang.rwv.dev" },
      { id: "notesPlain", label: "notesPlain", type: "STRING", purpose: "NOTES",
        value: `Full Tang private key backup. Active: ${set.active.length}; retired: ${set.retired.length}. Created ${createdAt}. Never remove retired exchange keys while clients still depend on them. This backup is created before deployment and may be a pending generation.` },
    ],
  };
  const item = JSON.parse(command("op", ["item", "create", "--vault", vault, "--format", "json", "-"], JSON.stringify(template)));
  if (typeof item.id !== "string") throw new Error("1Password did not return an item ID");
  const state: State = { itemId: item.id, vault, createdAt, thumbprints };
  const restored = readBackup(state);
  if (JSON.stringify(restored) !== value) throw new Error("1Password backup read-back mismatch");
  writeFileSync(statePath, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
  console.log(`Verified 1Password backup: ${item.id} (${vault}); active=${set.active.length}, retired=${set.retired.length}`);
  console.log(`Active thumbprints: ${thumbprints.join(", ")}`);
  return state;
}

async function main() {
  const action = process.argv[2];
  if (action === "init") {
    if (existsSync(statePath)) throw new Error("State already exists. Use deploy to reuse it; use rotate to generate a new pair.");
    await saveBackup({ version: 1, active: [generateSigningKey(), generateExchangeKey()], retired: [] });
  } else if (action === "rotate") {
    const previous = readBackup(readState());
    await saveBackup({ version: 1, active: [generateSigningKey(), generateExchangeKey()],
      retired: [...previous.retired, ...previous.active] });
    console.log("New generation backed up. Run deploy, then verify the new and retired keys.");
  } else if (action === "deploy" || action === "dry-run") {
    const state = readState();
    const set = readBackup(state);
    await validateForDeployment(set);
    const directory = mkdtempSync(join(tmpdir(), "tang-edge-"));
    try {
      const path = join(directory, "secrets.json");
      writeFileSync(path, JSON.stringify({ TANG_KEYSET: JSON.stringify(set) }), { mode: 0o600 });
      const args = ["deploy", "--config", configPath, "--secrets-file", path];
      if (action === "dry-run") args.push("--dry-run", "--outdir", join(directory, "build"));
      const output = command(wrangler, args, undefined, { WRANGLER_LOG_PATH: join(directory, "logs") });
      // Only show deployment metadata, never binding values or credential command output.
      for (const line of output.split("\n")) {
        if (/^(Total Upload:|Uploaded tang-edge|Deployed tang-edge|Current Version ID:|Worker Startup Time:|--dry-run:)/.test(line)
          || /^\s+(tang\.rwv\.dev|https:\/\/tang\.rwv\.dev)/.test(line)) console.log(line);
      }
    } finally { rmSync(directory, { recursive: true, force: true }); }
  } else if (action === "status") {
    const state = readState();
    const set = readBackup(state);
    console.log(JSON.stringify({ ...state, active: set.active.length, retired: set.retired.length }, null, 2));
  } else {
    throw new Error("Usage: bun run scripts/cloudflare-secrets.ts init|rotate|deploy|dry-run|status");
  }
}
await main().catch(error => { console.error(error.message); process.exitCode = 1; });
