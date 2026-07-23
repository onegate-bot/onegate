# Security Policy

OneGate is a credential gateway: it holds real vendor credentials and terminates TLS for the hosts it manages. Security reports are taken seriously and handled quickly.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting on this repository ("Security" tab → "Report a vulnerability"). If that is unavailable, contact the maintainer directly via GitHub ([@zivisaiah](https://github.com/zivisaiah)).

Please include: affected component (proxy, CA, admin API, an integration), reproduction steps, and impact. You can expect an acknowledgment within a few days.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Threat model

The threat model, trust boundaries, and the reasoning behind the CA / TLS-termination design are documented in [docs/SECURITY.md](docs/SECURITY.md). Reading it first will help you classify what is and is not a vulnerability (for example, the gateway intentionally terminates TLS for integration hosts using its own install-time root CA).
