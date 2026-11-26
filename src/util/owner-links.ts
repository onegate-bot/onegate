/**
 * Who may see an owner link, and what it takes to redeem one.
 *
 * Approve (`/approve/<token>`) and renew (`/renew/<token>`) links are bearer
 * capabilities: whoever holds the token can approve a held call or re-open a
 * lapsed access lease. Handing one to the AGENT whose call was held lets the
 * agent approve its own call, which defeats `require_approval` and lease
 * time-boxing entirely. So by default these links only go to the owner (the
 * notify webhook) and never appear in a response to the agent.
 *
 * Some deployments have a chat bot relay the link to its owner (the bot IS the
 * owner's notification channel). `ONEGATE_AGENT_RELAYS_OWNER_LINKS=1` restores
 * the link in the agent's 403 for them, and in exchange every approve/renew
 * decision then requires a second factor the agent never sees: the owner PIN
 * (set with `onegate approvals pin set`) or the admin token. Wrong answers are
 * counted per link and the link locks after OWNER_LINK_MAX_PIN_FAILURES, so a
 * short PIN cannot be brute forced through a link the agent holds.
 */

import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

/** Opt-in env var that puts approve/renew links back into agent responses. */
export const AGENT_RELAYS_OWNER_LINKS_ENV = "ONEGATE_AGENT_RELAYS_OWNER_LINKS";

/** Settings key holding the scrypt hash of the owner PIN. Replicates in a cluster. */
export const OWNER_PIN_SETTING = "owner_link_pin_hash";

/** Wrong second-factor attempts a single link tolerates before it locks. */
export const OWNER_LINK_MAX_PIN_FAILURES = 5;

/** True when the operator opted into agents relaying owner links. */
export function agentRelaysOwnerLinksFromEnv(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env[AGENT_RELAYS_OWNER_LINKS_ENV] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/** The startup warning printed when the opt-in is set. */
export function agentRelaysOwnerLinksWarning(pinSet: boolean): string {
  return (
    `onegate: ${AGENT_RELAYS_OWNER_LINKS_ENV} is set, so approve and renew links are returned to agents. ` +
    "Every decision on them requires the owner PIN or the admin token" +
    (pinSet ? "." : " (no owner PIN is set: only the admin token works; set one with `onegate approvals pin set`).") +
    " Unset it unless your bot relays these links to its owner."
  );
}

/** Returns an error message for an unusable PIN, or null when it is acceptable. */
export function ownerPinProblem(pin: unknown): string | null {
  if (typeof pin !== "string") return "pin must be a string";
  if (pin.length < 4 || pin.length > 64) return "pin must be 4 to 64 characters";
  if (/\s/.test(pin)) return "pin must not contain whitespace";
  return null;
}

const SCRYPT_KEYLEN = 32;

/** scrypt hash of a PIN, as `scrypt$<salt hex>$<hash hex>`. */
export function hashOwnerPin(pin: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(pin, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}

/** Timing-safe check of a PIN against a stored hashOwnerPin() value. */
export function verifyOwnerPin(pin: string, stored: string | null): boolean {
  if (!stored) return false;
  const [scheme, saltHex, hashHex] = stored.split("$");
  if (scheme !== "scrypt" || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  if (expected.length !== SCRYPT_KEYLEN) return false;
  const given = scryptSync(pin, Buffer.from(saltHex, "hex"), SCRYPT_KEYLEN);
  return timingSafeEqual(given, expected);
}
