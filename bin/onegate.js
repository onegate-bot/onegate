#!/usr/bin/env node
import { main } from "../dist/cli.js";

main().catch((err) => {
  console.error(`onegate: ${err.message}`);
  process.exit(1);
});
