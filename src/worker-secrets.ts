// SPDX-License-Identifier: GPL-3.0-only
import { createApp } from "./app";
import { WorkerSecretStorage } from "./storage/adapters/worker-secret";

export const app = createApp();

export default {
  async fetch(req: Request, env: Cloudflare.Env, ctx: ExecutionContext) {
    try {
      const storage = await WorkerSecretStorage.create(env.TANG_KEYSET);
      return await app.fetch(req, { TANG_KEYS: storage }, ctx);
    } catch {
      // Do not log parser errors or secret contents.
      return new Response("Tang key configuration unavailable", { status: 503,
        headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    }
  },
} satisfies ExportedHandler<Cloudflare.Env>;
