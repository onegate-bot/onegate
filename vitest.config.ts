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
      // changes pass, but a meaningful slide fails the build. Raised from
      // 90/90/94/84 once proxy, admin and CLI were covered (#125, #126).
      //
      // The globs are per-component floors: each one is checked against the
      // files it matches, so a well-covered component cannot hide a weak one
      // behind the global number. Every component must stay above 90% lines
      // and statements. Add a glob here when adding a new top-level module.
      thresholds: {
        lines: 95,
        statements: 94,
        functions: 96,
        branches: 88,
        "src/proxy/**": { lines: 90, statements: 90, functions: 90, branches: 85 },
        "src/admin/**": { lines: 90, statements: 90, functions: 90, branches: 85 },
        "src/cli/**": { lines: 90, statements: 90, functions: 90, branches: 85 },
        "src/cluster/**": { lines: 90, statements: 90, functions: 90, branches: 85 },
        "src/store/**": { lines: 90, statements: 90, functions: 90, branches: 85 },
        "src/integrations/**": { lines: 90, statements: 90, functions: 90, branches: 85 },
        "src/llm/**": { lines: 90, statements: 90, functions: 90, branches: 85 },
        "src/util/**": { lines: 90, statements: 90, functions: 90, branches: 85 },
        "src/*.ts": { lines: 90, statements: 90, functions: 90, branches: 85 },
      },
    },
  },
});
