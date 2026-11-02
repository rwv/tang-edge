// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) tang-edge contributors

import { createApp } from "./app";
import type { Env } from "./storage/types";
import { CloudflareKVStorage } from "./storage/adapters/cloudflare-kv";
import { rotateAllKeys } from "./storage/kv-store";

interface CloudflareEnv {
  TANG_KEYS: KVNamespace;
  ROTATE_TOKEN?: string;
}

const app = createApp({ rotation: true });

function wrapEnv(cfEnv: CloudflareEnv): Env {
  return {
    TANG_KEYS: new CloudflareKVStorage(cfEnv.TANG_KEYS),
    ROTATE_TOKEN: cfEnv.ROTATE_TOKEN,
  };
}

export { app };

export default {
  fetch: (req: Request, env: CloudflareEnv, ctx: ExecutionContext) =>
    app.fetch(req, wrapEnv(env), ctx),
  scheduled: async (
    _event: ScheduledEvent,
    env: CloudflareEnv,
    _ctx: ExecutionContext,
  ) => {
    await rotateAllKeys(new CloudflareKVStorage(env.TANG_KEYS));
  },
};
