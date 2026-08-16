# Pi Sandbox Extension Plan

## Status

Implementation started under the package name `pi-guard`.

- **Phase 1:** implemented — package scaffold, versioned configuration, restrictive project merge, canonical project roots, hidden-path policy, filtered environment, explicit network hooks, Gondolin lifecycle, diagnostics, and fail-closed tool gating.
- **Phase 2:** implemented — Pi tool-factory overrides for Bash and all built-in filesystem tools, user Bash policy routing, third-party tool blocking, guest path normalization, cancellation/timeouts, streaming, truncation, rendering, result details, and mutation-queue compatibility.
- **Live security test:** implemented and passing with QEMU — VM boot/cleanup, workspace read/write-through, hidden files, same-workspace and escaping symlink denial, environment filtering, and deny-all networking.
- **Phase 3:** implemented — exact structured host-command rules, canonical-project filtering, serialized and timed approval, shell-free program/argv execution, cancellation and execution timeouts, standard output truncation, durable non-secret audit metadata, external-tool startup warnings, status, diagnostics, and policy explanation.
- **Phase 4:** implemented — expanded security regressions, VM and command failure injection, active cancellation and timeout tests, macOS/Linux CI jobs, isolated `pi install` smoke testing, machine-readable performance benchmarks, release metadata, security policy, and operator documentation. Local macOS verification is passing; both CI platforms must pass before release.

The original open questions are resolved in this document.

The extension is secure-by-default: model-controlled commands and filesystem tools run through Gondolin, network access is deny-by-default, host secrets are hidden, and host execution is available only through exact, user-owned command rules with explicit human approval.

## Problem

Pi and its extensions run with the current user's host permissions. In an untrusted repository, unattended workflow, or prompt-injection scenario, unrestricted tools can read host files, expose credentials, modify files outside the project, or execute arbitrary host commands.

A Bash-only sandbox is not a sufficient boundary because Pi's built-in filesystem tools and third-party tools can bypass Bash entirely. Conversely, moving the entire Pi process into Docker or another container makes host integration and existing project tooling harder, and exposing the Docker socket effectively grants powerful host control.

## Goal

Build one Pi package, `pi-guard`, that provides:

1. **Strict-by-default tool isolation** using a Gondolin Linux micro-VM.
2. **Deterministic filesystem policy** enforced by tool routing and Gondolin VFS providers, not shell-string inspection.
3. **Deny-by-default network access** with explicit hostname allowlists.
4. **Filtered guest environment variables** so host credentials never enter the VM accidentally.
5. **Narrow, human-approved host operations** represented as structured commands rather than arbitrary shell prefixes.

## Threat Model

### Protected assets

- Host files outside the project working directory.
- Sensitive files inside the project, such as `.env`, `.npmrc`, private keys, and credentials.
- Host environment variables, API keys, tokens, and Pi session metadata.
- Host services, localhost, cloud metadata endpoints, and internal networks.
- Host command execution and privileged interfaces such as the Docker socket.

### In-scope attacker

- Prompt-injected or malicious repository content influencing the model.
- Model-generated shell commands, file operations, or tool calls.
- Code running inside the Gondolin guest.
- Remote servers contacted by guest code.

### Trust assumptions

- Pi, the global `pi-guard` extension, Node.js, Gondolin, QEMU, and the host OS are trusted.
- The repository and project-controlled configuration are untrusted until explicitly trusted.
- The Gondolin guest image is trusted to the extent of its supply chain.
- User approval is meaningful only when the complete structured host operation is shown.

### Non-goals

The extension does not defend against:

- A malicious host user or malicious globally installed Pi extension.
- QEMU or hypervisor escape vulnerabilities.
- Denial of service through CPU, memory, disk, or excessive host-side work.
- Side-channel attacks.
- Exfiltration to a host the user explicitly allows when the guest can also read the data being exfiltrated.
- Arbitrary third-party Pi tools unless they are blocked, disabled, or explicitly brought under this policy.

## Security Invariants

These invariants must hold in `strict` mode:

1. No model-controlled tool executes a shell command directly on the host.
2. No model-controlled filesystem tool can access a host path outside the canonical project root.
3. Denied project paths are hidden at the VFS layer and blocked in Pi filesystem tools.
4. The guest receives no outbound network access unless the user explicitly configures allowed hosts.
5. The guest receives only allowlisted environment variables; secrets are never copied from `process.env` by default.
6. Project-controlled configuration can tighten policy but cannot weaken the global security floor.
7. Initialization, configuration, policy, or VM failures fail closed and never fall back to host execution.
8. Denied, cancelled, timed-out, or unavailable host approvals result in a blocked operation—not execution in a different environment.

## Architecture

```text
User / model
  │
  ▼
Pi host process + globally installed pi-guard extension
  │
  ├─ read/write/edit/ls/find/grep
  │    └─ Pi built-in tool implementations with Gondolin operations
  │         └─ /workspace VFS
  │              └─ ShadowProvider
  │                   └─ RealFSProvider(canonical project root)
  │
  ├─ bash
  │    └─ Gondolin VM
  │         ├─ filtered environment
  │         ├─ deny-by-default HTTP/TLS policy
  │         └─ isolated guest root filesystem and processes
  │
  ├─ host_command
  │    ├─ resolve a user-owned structured rule
  │    ├─ show exact executable + argv to user
  │    ├─ approve → direct host spawn without a shell
  │    └─ deny/cancel/timeout/headless → blocked
  │
  ├─ ! / !! user Bash
  │    └─ Gondolin by default; configurable only from global policy
  │
  └─ third-party tools
       ├─ explicitly approved by global policy → unchanged
       └─ unapproved in strict mode → blocked or disabled
```

## Policy Layers

### Layer 1: Global security floor

The extension loads user-owned global configuration first. This establishes rules that project configuration cannot weaken:

- Operating mode.
- Denied paths.
- Network ceiling.
- Environment allowlist.
- Structured host commands.
- Third-party tool allowlist.
- User Bash behavior.

Global configuration may contain path-keyed project policies for commands that should be available only in a particular canonical project root.

### Layer 2: Gondolin VFS policy

Mount only the canonical project root at `/workspace`.

Compose providers so the most security-sensitive policy is closest to the host filesystem:

```ts
const hostWorkspace = new RealFSProvider(canonicalProjectRoot);
const protectedWorkspace = new ShadowProvider(hostWorkspace, {
  shouldShadow: createShadowPathPredicate(deniedVfsPaths),
  writeMode: "deny",
  denySymlinkBypass: true,
});
```

Requirements:

- Resolve and canonicalize the host project root before mounting it.
- Hide denied files from reads and directory listings.
- Deny writes to hidden files.
- Rely on `RealFSProvider` containment and symlink protections for the mounted root.
- Do not mount the user's home directory, `/`, credential directories, Docker socket, or SSH agent socket.
- Keep guest-only paths such as `/tmp`, `/root`, and the image root ephemeral.

Default denied VFS paths include:

```text
/.env
/.env.*
/.npmrc
/.pypirc
/*.pem
/*.key
/secrets/**
/credentials/**
```

Global policy may add denied paths. Project policy may only add more denied paths.

### Layer 3: Pi filesystem tool routing

Override Pi's built-in `read`, `write`, `edit`, `ls`, `find`, `grep`, and `bash` tools using Pi's exported tool factories and Gondolin operation interfaces.

Requirements:

- Preserve the built-in parameter schemas, result shapes, rendering behavior, cancellation, timeouts, and truncation semantics.
- Normalize a leading `@` in path arguments consistently with built-in tools.
- Use the same canonical path conversion for every filesystem operation.
- Keep write/edit mutations compatible with Pi's file mutation queue.
- Never implement security using substring checks on raw paths alone.

The official Pi Gondolin example is the implementation starting point, but it must be hardened with `ShadowProvider`, explicit network policy, and environment filtering.

### Layer 4: Guest network and environment policy

Gondolin's VM boundary does not imply deny-by-default egress. The extension must always configure HTTP hooks explicitly.

Default network policy:

```ts
const { httpHooks } = createHttpHooks({
  allowedHosts: [],
  blockInternalRanges: true,
});
```

Rules:

- Empty `allowedHosts` means deny-all.
- Project configuration may narrow the global hostname set by intersection; it cannot add hosts beyond the global ceiling.
- Exact hosts are preferred over wildcards.
- Internal ranges remain blocked.
- Raw mapped TCP, outbound SSH, WebSockets, and ingress are disabled in the MVP.
- Later support for these features requires separate explicit policy and threat-model review.

Guest environment policy:

- Build a new environment object from an allowlist; never sanitize by copying every string from `process.env`.
- Permit only basic non-secret values by default, for example `PATH`, `LANG`, selected `LC_*`, `TERM`, `CI`, and a guest-specific `HOME`.
- Do not expose host `HOME`, `SSH_AUTH_SOCK`, cloud variables, package registry tokens, API keys, or Pi session file paths.
- Configuration may define literal guest values, but secrets should use Gondolin's mediated secret mechanism only in a separately reviewed phase.

### Layer 5: Structured host operations

Do not use `preflightCommandPrefixes` and do not promote arbitrary Bash strings to the host.

Register a separate `host_command` tool. The tool accepts a rule identifier and, in a later version, schema-constrained parameters. In the MVP, each rule maps to one exact executable and exact argv array.

Example global configuration:

```json
{
  "hostCommands": {
    "docker-django-tests": {
      "description": "Run the Django test suite in the project's app container",
      "projectRoot": "/absolute/canonical/path/to/project",
      "program": "docker",
      "args": [
        "compose",
        "exec",
        "app",
        "python",
        "manage.py",
        "test"
      ],
      "cwd": "/absolute/canonical/path/to/project",
      "timeoutSeconds": 900
    }
  }
}
```

Execution requirements:

- Rules come only from user-owned global configuration.
- Match the canonical current project root before offering a rule.
- Display the exact program, argv, cwd, and timeout.
- Require `ctx.ui.confirm()` for every execution in the MVP.
- Spawn the executable directly with argv; do not invoke `sh -c`, `bash -c`, or interpolate a shell string.
- In print/JSON mode, missing UI, cancellation, denial, or timeout blocks the call.
- Capture and truncate output using Pi's standard command-output limits.
- Audit approval outcome and execution metadata without recording secret environment values.

A rejected host operation is not retried in Gondolin automatically. If sandbox execution is useful, the model must make a separate Bash call whose environment and side effects are clear.

### Layer 6: Third-party tools

A sandbox cannot constrain arbitrary extensions that execute host code internally.

In strict mode:

- Disable or block `fffind` and `ffgrep` unless they gain equivalent path filtering, because they expose host-indexed names and content.
- Inspect active tools at session startup.
- Block model calls to unapproved non-core tools using `tool_call` policy.
- Allow third-party tools only through a user-owned global allowlist.
- Show a startup warning listing blocked or explicitly trusted external tools.

The tool allowlist is a security decision, not a convenience setting. Project configuration cannot add tools to it.

## Configuration

### Global configuration

Path:

```text
~/.pi/agent/pi-guard.json
```

Use `getAgentDir()` rather than hardcoding the agent directory.

```json
{
  "version": 1,
  "mode": "strict",
  "filesystem": {
    "deny": [
      "/.env",
      "/.env.*",
      "/.npmrc",
      "/.pypirc",
      "/*.pem",
      "/*.key",
      "/secrets/**",
      "/credentials/**"
    ],
    "workspaceAccess": "read-write"
  },
  "network": {
    "allowedHosts": [],
    "blockInternalRanges": true
  },
  "environment": {
    "allowFromHost": ["LANG", "LC_*", "TERM", "CI"],
    "values": {
      "HOME": "/root",
      "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    }
  },
  "hostCommands": {},
  "externalTools": {
    "allow": []
  },
  "userBash": "sandbox",
  "approvalTimeoutSeconds": 60
}
```

### Project configuration

Path:

```text
<project>/.pi/pi-guard.json
```

Use `CONFIG_DIR_NAME` rather than hardcoding `.pi`.

Project configuration is read only when `ctx.isProjectTrusted()` is true. Even when trusted, it may only tighten policy:

```json
{
  "version": 1,
  "filesystem": {
    "deny": ["/private-fixtures/**"]
  },
  "network": {
    "allowedHosts": []
  }
}
```

Project configuration cannot:

- Disable strict mode.
- Add or modify host commands.
- Add environment variables.
- Add external tools.
- Expand filesystem access.
- Expand the global network allowlist.

### Merge semantics

- Denied paths: union.
- Allowed network hosts: intersection with the global ceiling.
- Workspace access: choose the more restrictive value.
- Environment and external tools: global-only.
- Host commands: global-only and filtered by canonical project root.
- Unknown keys or unsupported config versions: startup error and fail closed.
- Malformed global configuration: fail closed.
- Malformed project configuration: fail closed in strict mode and report the exact file and validation error.

Use a strict versioned schema and reject ambiguous values rather than silently ignoring them.

## Modes

### `strict` — default

- All built-in command and filesystem tools route through Gondolin.
- Network is deny-by-default.
- Environment is allowlist-only.
- Unapproved third-party tools are blocked.
- Structured host commands require confirmation.
- Any initialization failure blocks affected tools.

### `compatible`

- Bash remains sandboxed.
- Selected host filesystem or third-party tools may remain active.
- The UI must clearly state that this is not a complete security boundary.
- This mode may be enabled only by global user-owned configuration.

### `disabled`

- The package registers status and diagnostic commands but does not replace tools.
- This mode may be enabled only by global user-owned configuration.
- The UI must display a persistent warning.

## Project Trust and Installation

Install `pi-guard` globally for use with untrusted repositories:

```bash
pi install npm:pi-guard
```

Do not rely on a project-local extension for the security boundary. Pi loads project-local extensions only after project trust, and trusted project extensions execute with full host permissions.

For untrusted repositories:

- Keep the Pi project untrusted.
- Use the globally installed sandbox extension.
- Do not load repository-provided extensions, skills, or executable configuration.
- Store host command permissions in global user-owned configuration, optionally scoped to the canonical project root.

## Lifecycle and Failure Behavior

- The extension factory registers tools and handlers but does not start long-lived resources.
- Start or lazily initialize the VM from `session_start` or the first routed tool call.
- Deduplicate concurrent startup with a shared initialization promise.
- Close the VM idempotently during `session_shutdown`.
- Update a compact status indicator with `starting`, `strict`, `compatible`, `blocked`, or `stopping` state.
- A VM crash invalidates the current instance; subsequent operations may attempt a clean restart but never fall back to host execution.
- Abort signals and tool timeouts must propagate into VM and host-command operations.
- Concurrent host approval prompts must be serialized. Pi preflights `tool_call` events sequentially, so approval gating should occur there or through an explicit extension queue rather than racing inside parallel tool executions.

## Package and Dependencies

Package structure:

```text
pi-guard/
├── package.json
├── src/
│   ├── index.ts
│   ├── config.ts
│   ├── policy.ts
│   ├── gondolin.ts
│   ├── tools.ts
│   ├── host-command.ts
│   └── diagnostics.ts
├── schemas/
│   └── config.schema.json
├── templates/
│   └── AGENTS.md
└── test/
```

`package.json`:

```json
{
  "name": "pi-guard",
  "keywords": ["pi-package"],
  "type": "module",
  "pi": {
    "extensions": ["./src/index.ts"]
  },
  "dependencies": {
    "@earendil-works/gondolin": "0.12.0"
  },
  "peerDependencies": {
    "@earendil-works/pi-coding-agent": "*",
    "typebox": "*"
  },
  "engines": {
    "node": ">=23.6.0"
  }
}
```

Do not vendor Gondolin. Pi installs runtime dependencies automatically for npm and git packages.

External/runtime prerequisites:

- Node.js 23.6 or newer.
- QEMU on macOS or Linux.
- Gondolin guest assets, downloaded and cached on first use.
- No Windows support in the MVP.

Add `/guard-doctor` to check runtime version, QEMU availability, asset initialization, configuration validity, canonical project root, network policy, blocked tools, and effective mode.

Do not publish unverified fixed performance claims. Measure cold start, warm execution latency, resident memory, and asset disk use on supported platforms before documenting numbers.

## User Experience

Register:

- `/guard` — show effective mode and a redacted policy summary.
- `/guard-doctor` — run diagnostics.
- `/guard-explain <path-or-rule>` — explain why access is allowed or denied without executing it.
- `host_command` — invoke a configured structured host rule.

Startup status should make the boundary visible:

```text
Pi Guard: strict · VM ready · network deny-all · 2 external tools blocked
```

Never claim that a session is secure when running in compatible/disabled mode or when policy initialization failed.

## AGENTS.md Guidance

```markdown
# Development environment

- Model-controlled shell and filesystem operations run in a Gondolin Linux VM.
- The host project is mounted at `/workspace`; writes under allowed paths persist to the host.
- Sensitive files and paths may appear not to exist because policy hides them.
- Network access is denied unless the user configured specific hosts.
- Host commands are exposed as named structured operations and require user approval.
- If a tool is blocked, do not search for a bypass. Report the blocked operation and reason.
- A rejected host operation is blocked; do not assume it ran in another environment.
```

The extension should also amend the effective system prompt in strict mode so the model sees `/workspace` as its working directory and understands the sandbox policy without relying solely on repository-controlled `AGENTS.md`.

## What We Build

The MVP includes:

1. Versioned global/project configuration with one-way restrictive merge semantics.
2. Gondolin lifecycle management with hardened VFS, network, and environment configuration.
3. Overrides for Pi's built-in Bash and filesystem tools.
4. Strict-mode third-party tool blocking and diagnostics.
5. Exact structured host commands with serialized human approval.
6. Status, doctor, explain, documentation, and security regression tests.

## What We Do Not Build in the MVP

- LLM-based permission decisions.
- Arbitrary host Bash forwarding or command-prefix matching.
- Docker socket, SSH agent, home directory, or root filesystem mounts.
- Raw TCP mappings, outbound SSH, WebSockets, or guest ingress.
- Secret injection into guest requests.
- Parameterized host-command templates.
- Windows support.
- A custom approval-dialog framework; use Pi's `ctx.ui.confirm()`.
- Claims that arbitrary third-party extensions are sandboxed.

## Resolved Decisions

1. **Filesystem interception:** yes; route all built-in filesystem tools through Gondolin in strict mode.
2. **Strict mode:** yes; strict is the default. Compatible and disabled modes are global opt-ins with visible warnings.
3. **Gondolin dependency:** declare it as a normal runtime dependency. QEMU and the required Node version remain diagnosed system prerequisites.
4. **Configuration scopes:** support global and project files, but project configuration may only tighten policy. Host commands and trust-expanding settings are global-only.
5. **Host exceptions:** use a separate structured tool with exact executable/argv rules, not Bash prefixes.
6. **Approval denial:** block; never silently reroute to the sandbox.
7. **Network default:** explicit deny-all.
8. **FFF integration:** disable `fffind`/`ffgrep` in strict mode until equivalent path policy exists.

## Implementation Phases

### Phase 1: Security core

- Configuration schema, validation, and restrictive merge.
- Canonical project-root handling.
- Gondolin lifecycle.
- `ShadowProvider` workspace and environment allowlist.
- Explicit deny-all network policy.

### Phase 2: Tool routing

- Override `read`, `write`, `edit`, `ls`, `find`, `grep`, and `bash` using Pi tool factories.
- Route user Bash according to global policy.
- Block unapproved third-party tools.
- Preserve cancellation, output truncation, rendering, and result details.

### Phase 3: Host operations and UX

- Exact structured `host_command` rules.
- Serialized `ctx.ui.confirm()` approval.
- Direct executable/argv spawning.
- Status, `/guard`, `/guard-doctor`, and `/guard-explain`.

### Phase 4: Hardening and release

Implemented:

- Security regression suite, including the gated real-QEMU boundary test.
- macOS and Linux unit, package-install, and live integration CI jobs.
- VM startup/probe failure injection plus active cancellation and timeout tests.
- Isolated package installation test through `pi install` using a temporary agent directory.
- Machine-readable local performance benchmark and operator/release documentation.

Release gate: `npm run verify:release`, `npm run test:live`, and both CI platforms must pass. Benchmark results remain machine-specific and are not fixed product claims.

## Acceptance Tests

### Filesystem

- Reading `.env` fails through Bash and every filesystem/search tool.
- Denied files are omitted from directory listings and searches.
- Absolute paths, `..`, symlinks, dangling symlinks, and `@`-prefixed paths cannot escape the workspace.
- Allowed workspace edits persist to the host.
- Host files outside the workspace remain inaccessible.

### Command and environment

- Ordinary Bash runs in the guest.
- Guest commands cannot see host API keys, tokens, SSH agent, host home path, or Pi session file.
- `sudo`, shell substitutions, pipelines, and redirections do not create a host-execution path.
- VM startup or execution failure never invokes host Bash.

### Network

- Zero-config guest HTTP/TLS requests fail.
- Allowed exact hosts work when globally configured.
- Unlisted hosts, redirects to unlisted hosts, localhost, metadata addresses, and internal ranges fail.
- Project configuration cannot broaden the global allowlist.

### Host commands

- Only globally configured rules for the canonical current project are visible.
- Exact program and argv are shown before approval.
- Approval executes without a shell.
- Denial, timeout, cancellation, and headless mode block execution.
- Multiple parallel requests cannot create overlapping approval dialogs.

### Tool ecosystem and trust

- `fffind` and `ffgrep` are unavailable in strict mode unless globally approved as policy-aware.
- Unknown external tools are blocked in strict mode unless globally allowed.
- Project configuration cannot approve tools or host commands.
- An untrusted project's local extensions do not participate in the sandbox session.

## Risks and Follow-up Work

- Gondolin 0.12.0 and its APIs may evolve; pin the dependency and test upgrades deliberately.
- QEMU remains a critical isolation dependency and must be kept current.
- The default Alpine image may lack project runtimes or packages; custom-image support needs a separate design.
- Real host workspaces mean allowed guest writes are persistent; future snapshot/overlay workflows may reduce accidental modification risk.
- Fine-grained parameterized host commands need per-rule schemas and escaping-free argv construction.
- Policy-aware FFF integration requires changes in `@ff-labs/pi-fff` or a filtered indexing layer.

## References

- Pi extensions: `docs/extensions.md`
- Pi packages: `docs/packages.md`
- Pi Gondolin example: `examples/extensions/gondolin/`
- Pi sandbox-runtime example: `examples/extensions/sandbox/`
- Gondolin security design: <https://github.com/earendil-works/gondolin/blob/main/docs/security.md>
- Gondolin limitations: <https://github.com/earendil-works/gondolin/blob/main/docs/limitations.md>
- Gondolin VFS providers: <https://earendil-works.github.io/gondolin/vfs/>
- Gondolin network SDK: <https://earendil-works.github.io/gondolin/sdk-network/>
- Pi Gondolin network-default issue: <https://github.com/earendil-works/pi/issues/6297>
- `sandbox-exec` deprecation: <https://keith.github.io/xcode-man-pages/sandbox-exec.1.html>
