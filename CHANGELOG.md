# Changelog

All notable changes to Pi Guard are documented here.

## 0.1.0 - 2026-08-16

### Added

- Strict-by-default Gondolin VM lifecycle with hardened VFS, deny-by-default network hooks, and filtered guest environment.
- Routed Pi `read`, `write`, `edit`, `ls`, `find`, `grep`, and `bash` tools with preserved tool contracts.
- Exact global-only structured host commands with serialized interactive approval and durable audit metadata.
- Status, diagnostics, policy explanation, security regression tests, live QEMU tests, cross-platform CI, package-install smoke testing, benchmarks, and operator documentation.

### Security

- Project policy can only tighten global policy and is ignored unless the project is trusted.
- VM and policy failures fail closed without host execution fallback.
- Unapproved third-party tools are disabled and blocked in strict mode.
