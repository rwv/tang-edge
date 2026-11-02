// SPDX-License-Identifier: GPL-3.0-only
import type { TangStorage } from "../interface";
import type { ECPrivateJWK } from "../types";
import { jwkThumbprint, isValidForSigning, isValidForDeriving } from "../../crypto/jwk-utils";

export interface SecretKeySet {
  version: 1;
  active: ECPrivateJWK[];
  retired: ECPrivateJWK[];
}

function isPrivateKey(key: unknown): key is ECPrivateJWK {
  if (!key || typeof key !== "object") return false;
  const k = key as Record<string, unknown>;
  return k.kty === "EC" && k.crv === "P-521"
    && [k.x, k.y, k.d].every(v => typeof v === "string" && /^[A-Za-z0-9_-]{88}$/.test(v))
    && Array.isArray(k.key_ops) && k.key_ops.every(v => typeof v === "string")
    && ((k.alg === "ES512" && k.key_ops.includes("sign") && k.key_ops.includes("verify"))
      || (k.alg === "ECMR" && k.key_ops.includes("deriveKey")));
}

export function parseKeySet(value: string): SecretKeySet {
  const data: unknown = JSON.parse(value);
  if (!data || typeof data !== "object") throw new Error("Invalid Tang key set");
  const set = data as Record<string, unknown>;
  if (set.version !== 1 || !Array.isArray(set.active) || !Array.isArray(set.retired)
    || !set.active.every(isPrivateKey) || !set.retired.every(isPrivateKey)
    || !set.active.some(isValidForSigning) || !set.active.some(isValidForDeriving)) {
    throw new Error("Invalid Tang key set");
  }
  return { version: 1, active: set.active, retired: set.retired };
}

/** Immutable snapshot: updates require a new secret and Worker deployment. */
export class WorkerSecretStorage implements TangStorage {
  private constructor(private readonly keys: ReadonlyMap<string, string>) {}

  static async create(value: string): Promise<WorkerSecretStorage> {
    const set = parseKeySet(value);
    const keys = new Map<string, string>();
    const seen = new Set<string>();
    for (const [group, retired] of [[set.active, false], [set.retired, true]] as const) {
      for (const key of group) {
        const thumbprint = await jwkThumbprint(key);
        if (seen.has(thumbprint)) throw new Error("Duplicate Tang key");
        seen.add(thumbprint);
        keys.set(`${retired ? "." : ""}${thumbprint}.jwk`, JSON.stringify(key));
      }
    }
    return new WorkerSecretStorage(keys);
  }

  async get(key: string) { return this.keys.get(key) ?? null; }
  async list() { return { keys: Array.from(this.keys.keys(), name => ({ name })) }; }
  async put(_key: string, _value: string): Promise<void> { throw new Error("Tang keys are read-only"); }
  async delete(_key: string): Promise<void> { throw new Error("Tang keys are read-only"); }
}
