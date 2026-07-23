/**
 * GitHub integration. One stored personal access token (classic or
 * fine-grained) covers both the REST API and git-over-HTTPS:
 *
 *  - api.github.com / uploads.github.com → `Authorization: Bearer <pat>`
 *  - github.com / codeload.github.com (git smart HTTP, archive downloads)
 *    → `Authorization: Basic x-access-token:<pat>`
 */

import type { Integration, InjectionContext } from "./types.js";

const GIT_HOSTS = new Set(["github.com", "codeload.github.com"]);

export const github: Integration = {
  id: "github",
  title: "GitHub",
  hosts: ["api.github.com", "uploads.github.com", "github.com", "codeload.github.com"],
  category: "Developer",
  credentialFields: [{ key: "pat", label: "Personal access token", secret: true }],
  llmHelp: {
    credentialType:
      "A GitHub personal access token (PAT). Either a fine-grained token or a classic token works. OneGate sends it as a Bearer token to the REST API and as Basic auth (user x-access-token) for git over HTTPS and archive downloads.",
    whereToCreate:
      "https://github.com/settings/tokens (on github.com go to Settings, then Developer settings, then Personal access tokens, and pick fine-grained or classic).",
    scopes: [
      'Classic token: the "repo" scope covers code, issues, pull requests and releases on private repositories. Add "read:org" for organization data and "workflow" only if the agent edits GitHub Actions workflow files.',
      "Fine-grained token: select the repositories the agent should reach, then grant Contents (read and write), Issues, Pull requests and Metadata. Add more permissions only if the agent needs them.",
    ],
    notes:
      'In OneGate\'s connect form, paste the token into the single field labeled "Personal access token". The "Credential name" field is just a display label, any name works.',
  },
  inject(ctx: InjectionContext): void {
    const pat = ctx.credential.data.pat;
    if (!pat) throw new Error("GitHub credential has no \"pat\" field");
    if (GIT_HOSTS.has(ctx.host)) {
      const basic = Buffer.from(`x-access-token:${pat}`).toString("base64");
      ctx.headers.authorization = `Basic ${basic}`;
    } else {
      ctx.headers.authorization = `Bearer ${pat}`;
    }
    // GitHub rejects requests without a User-Agent.
    if (!ctx.headers["user-agent"]) ctx.headers["user-agent"] = "onegate";
  },
};
