/**
 * JFrog Artifactory access token, injected as Bearer. The credential stores the
 * instance host and inject refuses to put the token on any other host, so a
 * policy that allows the .jfrog.io dot-suffix cannot leak the token to someone
 * else's tenant.
 *
 * SELF-MANAGED INSTANCES: Artifactory is commonly run on the owner's own
 * domain, not just *.jfrog.io, so this integration declares
 * `supportsInstanceOrigin`. A connection may name that domain (e.g.
 * https://artifactory.acme.example), which makes the host resolve here and pins
 * injection to the connection that claimed it. Injection is unchanged and stays
 * host-bound: set the credential's `host` field to the same domain, and the
 * existing equality check below keeps the token on that host only. The two
 * guards are independent and both must agree, which is deliberate.
 */

import type { Integration, InjectionContext } from "./types.js";

export const jfrogArtifactory: Integration = {
  id: "jfrog-artifactory",
  title: "JFrog Artifactory",
  hosts: [".jfrog.io"],
  category: "Developer",
  supportsInstanceOrigin: true,
  credentialFields: [
    { key: "token", label: "Access token", secret: true },
    { key: "host", label: "Instance host (e.g. acme.jfrog.io)", secret: false },
  ],
  connect: {
    method: "api_key",
    hint: "An Artifactory access token plus your instance host (cloud like acme.jfrog.io, or your own self-managed domain). The token is only ever sent to that host.",
  },
  llmHelp: {
    credentialType:
      "A JFrog access token (long JWT starting with eyJ) plus the instance host like acme.jfrog.io. OneGate injects the token as Bearer, and only on that exact host.",
    whereToCreate:
      "JFrog Platform UI on your instance: Administration, then User Management, then Access Tokens (or your profile, Generate Identity Token). Scoped tokens with an expiry are preferred.",
    scopes: [
      "Scope the token to the repositories the agent needs (read for pulling packages, deploy for publishing).",
    ],
    notes:
      "Typical use is pulling npm or PyPI packages through a remote repo: point the package manager at https://<host>/artifactory/api/npm/<repo>/ and let OneGate add the auth. Self-managed Artifactory on your own domain is supported: set the connection's instance origin to that https domain and use the same host in the credential.",
  },
  inject(ctx: InjectionContext): void {
    const { token, host } = ctx.credential.data;
    if (!token || !host) {
      throw new Error('JFrog credential needs "token" and "host" (e.g. acme.jfrog.io)');
    }
    if (ctx.host.toLowerCase() !== host.toLowerCase()) {
      throw new Error(
        `JFrog credential is bound to ${host}, refusing to authenticate ${ctx.host}`,
      );
    }
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
