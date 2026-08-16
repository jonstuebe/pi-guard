# pi-guard

Strict-by-default Gondolin sandbox extension for Pi.

> **Development status:** Phases 1–4 are implemented for the unreleased `0.1.0` line. Strict routing, approved structured host operations, failure injection, live QEMU regressions, package-install smoke tests, benchmarks, and macOS/Linux CI are present. Cross-platform CI must pass before publishing a release.

## Requirements

- Node.js 23.6+
- QEMU on macOS or Linux
- Pi

## Development

```bash
npm install
npm run verify
npm run test:install   # isolated pi install smoke test
npm run test:live          # boots Gondolin; requires QEMU
npm run test:live:network  # public-network allowlist regression
npm run benchmark          # local JSON measurements; requires QEMU
pi -e .
```

The live test verifies write-through behavior, hidden sensitive paths, symlink protections, guest environment filtering, deny-all networking, and VM cleanup.

Commands:

- `/guard` — show effective policy and VM state.
- `/guard-doctor` — check configuration, runtime prerequisites, network posture, and VM state.
- `/guard-explain [rule]` — explain the security boundary or show one exact host-command rule.

Configuration is loaded from `~/.pi/agent/pi-guard.json` and, for trusted projects only, `<project>/.pi/pi-guard.json`. Project configuration may only tighten global policy.

Host commands are global-only, canonical-project-scoped, and require approval on every call:

```json
{
  "version": 1,
  "hostCommands": {
    "project-tests": {
      "description": "Run the host test command",
      "projectRoot": "/absolute/canonical/project",
      "program": "npm",
      "args": ["test"],
      "cwd": "/absolute/canonical/project",
      "timeoutSeconds": 900
    }
  }
}
```

See:

- `docs/operator-guide.md` for installation, policy operation, incident response, release verification, and benchmarking.
- `docs/pi-sandbox-extension-plan.md` for the threat model, architecture, implementation phases, and acceptance criteria.
- `SECURITY.md` for vulnerability reporting and supported security boundaries.
