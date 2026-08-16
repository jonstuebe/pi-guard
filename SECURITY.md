# Security policy

## Supported versions

Until the first stable release, only the latest `0.1.x` revision is supported with security fixes.

## Reporting a vulnerability

Do not disclose a suspected sandbox bypass in a public issue. Contact the maintainer through the package registry or repository's private security-reporting channel and include:

- Pi Guard, Pi, Gondolin, Node.js, QEMU, and operating-system versions;
- effective redacted policy and mode;
- minimal reproduction steps;
- whether host data was read or modified;
- whether a host command or third-party extension was involved.

Never include real credentials or session files. Use synthetic secrets in reproductions.

## Security boundary

Strict mode routes Pi's built-in filesystem and Bash tools through Gondolin. It does not sandbox the Pi process, globally approved external tools, approved structured host commands, or malicious host extensions. Allowed workspace writes persist to the host. QEMU vulnerabilities, host-user compromise, side channels, and complete denial-of-service protection are outside the threat model.

Security-sensitive dependency upgrades must retain the pinned Gondolin version until the live QEMU regression suite passes on macOS and Linux.
