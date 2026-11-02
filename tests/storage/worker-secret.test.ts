// SPDX-License-Identifier: GPL-3.0-only
import { describe, it, expect } from "bun:test";
import worker from "../../src/worker-secrets";
import { WorkerSecretStorage, parseKeySet } from "../../src/storage/adapters/worker-secret";
import { generateSigningKey, generateExchangeKey } from "../../src/crypto/keygen";
import { jwkThumbprint, jwkPublic, base64urlDecode } from "../../src/crypto/jwk-utils";
import { ecmrExchange } from "../../src/crypto/ecmr";

const active = [generateSigningKey(), generateExchangeKey()];
const retired = [generateSigningKey(), generateExchangeKey()];
const keyset = JSON.stringify({ version: 1, active, retired });
const request = (path: string, init?: RequestInit, secret = keyset) => worker.fetch(
  new Request(`https://localhost${path}`, init), { TANG_KEYSET: secret }, {} as ExecutionContext,
);

describe("Worker Secret deployment", () => {
  it("advertises only active public keys and passes independent ES512 verification", async () => {
    const res = await request("/adv");
    expect(res.status).toBe(200);
    const jws = await res.json() as { payload: string; signatures: {protected:string;signature:string}[] };
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(jws.payload)));
    expect(payload.keys).toEqual(active.map(jwkPublic));
    expect(payload.keys.every((key: Record<string, unknown>) => !("d" in key))).toBe(true);
    const sig = jws.signatures[0];
    const k = active[0];
    const publicKey = await crypto.subtle.importKey("jwk", {kty:k.kty, crv:k.crv, x:k.x, y:k.y},
      {name:"ECDSA",namedCurve:"P-521"}, false, ["verify"]);
    expect(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-512"}, publicKey,
      base64urlDecode(sig.signature), new TextEncoder().encode(`${sig.protected}.${jws.payload}`))).toBe(true);
  });

  it("recovers using both current and retired exchange keys", async () => {
    const client = jwkPublic(generateExchangeKey());
    for (const serverKey of [active[1], retired[1]]) {
      const res = await request(`/rec/${await jwkThumbprint(serverKey)}`, {
        method: "POST", body: JSON.stringify(client),
      });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual(ecmrExchange(serverKey, client));
    }
  });

  it("still signs advertisements with a retired signing key on request", async () => {
    const res = await request(`/adv/${await jwkThumbprint(retired[0])}`);
    expect(res.status).toBe(200);
    expect((await res.json() as {signatures:unknown[]}).signatures).toHaveLength(2);
  });

  it("has no online rotation route or scheduled handler", async () => {
    expect((await request("/rotate", {method:"POST"})).status).toBe(404);
    expect("scheduled" in worker).toBe(false);
    const store = await WorkerSecretStorage.create(keyset);
    await expect(store.put("key", "value")).rejects.toThrow("read-only");
    await expect(store.delete("key")).rejects.toThrow("read-only");
  });

  it("fails closed without a usable active key pair", async () => {
    for (const value of ["", "null", "{}", JSON.stringify({version:1,active:[],retired}),
      JSON.stringify({version:1,active:[active[0]],retired}),
      JSON.stringify({version:1,active:[active[1]],retired})]) {
      expect((await request("/adv", undefined, value)).status).toBe(503);
    }
  });

  it("rejects duplicate keys and malformed private material", async () => {
    await expect(WorkerSecretStorage.create(JSON.stringify({version:1, active, retired:active})))
      .rejects.toThrow("Duplicate");
    expect(() => parseKeySet(JSON.stringify({version:1, active:[{...active[0],d:"bad"},active[1]], retired:[]})))
      .toThrow("Invalid Tang key set");
  });
});
