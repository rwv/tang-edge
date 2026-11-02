// SPDX-License-Identifier: GPL-3.0-only
// Public protocol smoke test; does not read or print any server private keys.
import { readFileSync } from "node:fs";
import { p521 } from "@noble/curves/nist.js";
import { base64urlDecode, base64urlToBigint, bigintToBase64url, jwkThumbprint } from "../src/crypto/jwk-utils";
import type { ECPublicJWK, TangJWS } from "../src/storage/types";

const url = (process.argv[2] ?? "https://tang.rwv.dev").replace(/\/$/, "");
function check(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
async function getAdvertisement(path: string): Promise<TangJWS> {
  const response = await fetch(`${url}${path}`, {signal:AbortSignal.timeout(20000)});
  check(response.status === 200, `${path}: HTTP ${response.status}`);
  return response.json();
}
async function verifyAdvertisement(jws: TangJWS, signingKey?: ECPublicJWK) {
  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(jws.payload))) as {keys:ECPublicJWK[]};
  check(payload.keys.length >= 2 && payload.keys.every(key => !("d" in key)), "Invalid public key advertisement");
  const key = signingKey ?? payload.keys.find(key => key.alg === "ES512");
  check(key, "Signing key missing");
  const imported = await crypto.subtle.importKey("jwk", {kty:key.kty, crv:key.crv, x:key.x, y:key.y},
    {name:"ECDSA",namedCurve:"P-521"}, false, ["verify"]);
  const results = await Promise.all(jws.signatures.map(sig => crypto.subtle.verify(
    {name:"ECDSA",hash:"SHA-512"}, imported, base64urlDecode(sig.signature),
    new TextEncoder().encode(`${sig.protected}.${jws.payload}`))));
  check(results.some(Boolean), "Independent ES512 verification failed");
  return payload.keys;
}
function point(key: ECPublicJWK) {
  const result = p521.Point.fromAffine({x:base64urlToBigint(key.x),y:base64urlToBigint(key.y)});
  result.assertValidity();
  return result;
}
function randomScalar() { return BigInt(`0x${Buffer.from(p521.utils.randomSecretKey()).toString("hex")}`); }
async function verifyRecovery(key: ECPublicJWK) {
  const ephemeral = randomScalar();
  const blind = randomScalar();
  const blinded = p521.Point.BASE.multiply(ephemeral).add(p521.Point.BASE.multiply(blind)).toAffine();
  const client: ECPublicJWK = {kty:"EC",crv:"P-521",alg:"ECMR",key_ops:["deriveKey"],
    x:bigintToBase64url(blinded.x),y:bigintToBase64url(blinded.y)};
  const response = await fetch(`${url}/rec/${await jwkThumbprint(key)}`, {method:"POST",
    headers:{"Content-Type":"application/jwk+json"}, body:JSON.stringify(client), signal:AbortSignal.timeout(20000)});
  check(response.status === 200, `Recovery: HTTP ${response.status}`);
  const server = point(key);
  const recovered = point(await response.json() as ECPublicJWK).subtract(server.multiply(blind));
  check(recovered.equals(server.multiply(ephemeral)), "Blinded ECMR recovery failed");
}

const health = await fetch(url, {signal:AbortSignal.timeout(20000)});
check(health.status === 200, `Health: HTTP ${health.status}`);
const advertisement = await getAdvertisement("/adv");
const keys = await verifyAdvertisement(advertisement);
for (const key of keys.filter(key => key.alg === "ECMR")) await verifyRecovery(key);
const signingKey = keys.find(key => key.alg === "ES512")!;
await verifyAdvertisement(await getAdvertisement(`/adv/${await jwkThumbprint(signingKey)}`), signingKey);
check((await fetch(`${url}/rotate`, {method:"POST",signal:AbortSignal.timeout(20000)})).status === 404,
  "Online rotation route is enabled");
if (process.argv[3]) {
  const previous = JSON.parse(readFileSync(process.argv[3], "utf8")) as TangJWS;
  const oldKeys = await verifyAdvertisement(previous);
  for (const key of oldKeys.filter(key => key.alg === "ECMR")) await verifyRecovery(key);
  const oldSigningKey = oldKeys.find(key => key.alg === "ES512")!;
  await verifyAdvertisement(await getAdvertisement(`/adv/${await jwkThumbprint(oldSigningKey)}`), oldSigningKey);
}
console.log(JSON.stringify({url,health:"ok",ES512:"verified",blindedECMR:"verified",onlineRotation:"disabled",
  previousKeys:process.argv[3] ? "verified" : "not supplied"}, null, 2));
