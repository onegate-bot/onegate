/**
 * JFrog Artifactory (cloud, *.jfrog.io) access token, injected as Bearer.
 * The credential stores the instance host and inject refuses to put the
 * token on any other *.jfrog.io tenant, so a policy that allows the
 * dot-suffix cannot leak the token to someone else's instance.
 */

import type { Integration, InjectionContext } from "./types.js";

export const jfrogArtifactory: Integration = {
  id: "jfrog-artifactory",
  title: "JFrog Artifactory",
  hosts: [".jfrog.io"],
  category: "Developer",
  credentialFields: [
    { key: "token", label: "Access token", secret: true },
    { key: "host", label: "Instance host (e.g. acme.jfrog.io)", secret: false },
  ],
  connect: {
    method: "api_key",
    hint: "An Artifactory access token plus your instance host. The token is only ever sent to that host.",
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
      "Typical use is pulling npm or PyPI packages through a remote repo: point the package manager at https://<host>/artifactory/api/npm/<repo>/ and let OneGate add the auth.",
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
