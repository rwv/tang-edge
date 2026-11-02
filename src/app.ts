// SPDX-License-Identifier: GPL-3.0-only
import { Hono } from "hono";
import { getPath } from "hono/utils/url";
import type { Env } from "./storage/types";
import adv from "./routes/adv";
import rec from "./routes/rec";
import rotate from "./routes/rotate";

export function createApp(options: { rotation?: boolean } = {}) {
  const app = new Hono<{ Bindings: Env }>({
    getPath: (req) => {
      const path = getPath(req);
      return path.length > 1 ? path.replace(/\/+$/, "") || "/" : path;
    },
  });
  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Cache-Control", "no-store");
  });
  app.route("/adv", adv);
  app.route("/rec", rec);
  if (options.rotation) app.route("/rotate", rotate);
  app.get("/", (c) => c.json({ service: "tang-edge", status: "ok" }));
  return app;
}
