# Pi Guard operator guide

## 1. Install globally before opening an untrusted project

Pi Guard must come from a user-owned location. Do not install it from the repository being evaluated.

```bash
# Local checkout during development
pi install /absolute/path/to/pi-guard

# Published package
pi install npm:@jonstuebe/pi-guard@<pinned-version>
```

Requirements:

- Node.js 23.6 or newer.
- QEMU available on `PATH` (`qemu-system-aarch64` or `qemu-system-x86_64`).
- macOS or Linux.

Run Pi Guard diagnostics after installation:

```text
/guard-doctor
```

The first guarded session may download Gondolin guest assets. Strict mode fails closed if assets, QEMU, configuration, or VM startup are unavailable.

## 2. Configure global policy

Global policy belongs at `~/.pi/agent/pi-guard.json`. Start with zero configuration whenever possible: strict mode, hidden secret paths, filtered environment, and deny-all networking are defaults.

Example with an exact network ceiling and one structured host command:

```json
{
  "version": 1,
  "mode": "strict",
  "network": {
    "allowedHosts": ["registry.npmjs.org"],
    "blockInternalRanges": true
  },
  "hostCommands": {
    "project-tests": {
      "description": "Run the project's host test suite",
      "projectRoot": "/absolute/canonical/project",
      "program": "npm",
      "args": ["test"],
      "cwd": "/absolute/canonical/project",
      "timeoutSeconds": 900
    }
  }
}
```

Use `pwd -P` to obtain a canonical project path. Host-command rules are visible only when `projectRoot` exactly matches the current canonical project. Every invocation displays the exact executable, argv, cwd, and timeout and requires approval.

Do not place credentials in host-command argv. Audit entries intentionally omit environment values, but exact argv is recorded as execution metadata.

## 3. Understand project policy and trust

A trusted project may add `<project>/.pi/pi-guard.json`, but it can only tighten policy:

- add hidden paths;
- reduce the global network allowlist;
- switch the workspace to read-only.

Project configuration cannot add host commands, approve external tools, forward user Bash to the host, broaden networking, or disable strict mode. Untrusted project configuration is ignored.

Use `/guard` for the effective redacted policy and `/guard-explain <path-or-rule>` for one decision.

## 4. Operate and respond to failures

A blocked state means host fallback did not occur. Fix the prerequisite or policy error; never bypass it by enabling repository-controlled extensions.

| Symptom | Action |
|---|---|
| QEMU missing | Install QEMU with the platform package manager and restart Pi. |
| Guest assets missing | Confirm outbound access for the initial asset download, then restart a guarded session. |
| VM blocked | Run `/guard-doctor`; inspect the reported startup error. |
| Command denied | Treat denial as final. Add an exact global rule only after reviewing the operation. |
| File appears missing | Check `/guard-explain <path>`; hidden paths deliberately look absent. |
| Tool disabled | Remove it or explicitly allow it globally only after confirming it enforces equivalent policy. |

Keep QEMU, Node.js, Pi, and Pi Guard patched. Pin Pi Guard versions in managed environments and rerun the live security suite after upgrades. GitHub-hosted macOS runners use test-only QEMU TCG because they do not expose HVF; normal Pi Guard sessions retain Gondolin's platform accelerator selection.

## 5. Verify releases and measure the local runtime

```bash
npm ci
npm run verify:release
npm run test:live
npm run test:live:network  # requires reliable outbound internet access
npm run benchmark
```

From a source checkout, `verify:release` runs type checking, unit/security regressions, an isolated `pi install` smoke test, and package inspection. `test:live` boots QEMU and validates the local boundary. `test:live:network` additionally validates an allowed exact host, an unlisted host, a redirect to an unlisted host, and a metadata address; it is separated because it depends on public internet services. Normal tests do not require QEMU.

The benchmark reports local cold VM startup, 20 warm command samples, host RSS delta, and Gondolin asset disk usage as JSON. Save a machine-specific result without committing it:

```bash
PI_GUARD_BENCH_OUTPUT=/tmp/pi-guard-benchmark.json npm run benchmark
```

Do not compare benchmark numbers across different hardware, operating systems, QEMU accelerators, Node versions, or cold/warm asset-cache states.

## Security boundary reminders

- Allowed workspace writes persist to the host.
- Compatible and disabled modes are not complete boundaries.
- Globally allowed third-party tools run in the host Pi process; Pi Guard cannot sandbox arbitrary extensions.
- Host commands run with the Pi process's host identity and inherited host environment after approval.
- The design does not claim protection from malicious host extensions/users, QEMU escapes, side channels, or complete denial of service.
