# Third-Party Notices

OneGate is licensed under the Apache License 2.0 (see LICENSE). This file documents third-party material included in or derived into this repository.

## simple-icons (MIT License)

The brand SVG icons vendored under `src/admin/ui/vendor/integration-icons/` (and copied into `dist/admin/ui/vendor/integration-icons/`) are derived from the simple-icons project.

- Project: simple-icons/simple-icons
- Source: https://github.com/simple-icons/simple-icons
- License: MIT (the icon path data is released under CC0 1.0)

Each `<id>.svg` was extracted from the simple-icons package at build time and wrapped as a standalone SVG that paints with `currentColor` so it adapts to the admin UI light and dark themes. The runtime serves only these vendored files and never imports the simple-icons package. The brand marks remain the property of their respective owners and are used here for identification only.
