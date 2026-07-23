/**
 * Shared CLI context. Carries the resolved host + token and lazily builds the
 * admin HTTP client or a direct store handle. Commands take a CliContext so
 * tests can inject a fake client/store without a live server.
 */

import { join } from "node:path";
import { homedir } from "node:os";
import { Store } from "../store/db.js";
import { AdminClient, resolveHost, resolveToken } from "./client.js";

export interface CliContext {
  /** Returns the admin HTTP client (built once). */
  client(): AdminClient;
  /** Opens a fresh direct store handle (caller must close it). */
  store(): Store;
}

function dataDir(): string {
  return process.env.ONEGATE_DATA ?? join(homedir(), ".onegate");
}

function dbPath(): string {
  return join(dataDir(), "onegate.db");
}

export interface ContextOptions {
  host?: string;
  token?: string;
}

/** Builds the real context used in production. */
export function createContext(opts: ContextOptions): CliContext {
  let cached: AdminClient | undefined;
  return {
    client() {
      if (!cached) {
        cached = new AdminClient({
          host: resolveHost(opts.host),
          token: resolveToken(opts.token),
        });
      }
      return cached;
    },
    store() {
      return new Store(dbPath());
    },
  };
}
