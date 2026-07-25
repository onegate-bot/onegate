import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["test/setup.ts"],
    testTimeout: 20_000,
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      // Server-side TypeScript only. The admin UI is browser code that ships as
      // plain .js (plus a checked-in third-party WebAwesome bundle) and is
      // exercised by the separate ui-smoke CI job, not by vitest.
      include: ["src/**/*.ts"],
      exclude: ["src/admin/ui/**"],
      // A floor, not a target. Set below the current numbers so ordinary
      // changes pass, but a meaningful slide fails the build.
      thresholds: {
        lines: 85,
        statements: 85,
        functions: 90,
        branches: 80,
      },
    },
  },
});
