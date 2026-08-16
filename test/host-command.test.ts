import assert from "node:assert/strict";
import test from "node:test";
import type { EffectiveGuardConfig } from "../src/config.js";
import {
	executeHostCommand,
	formatHostCommandApproval,
	HostCommandBlockedError,
	type HostCommandAuditEntry,
	SerializedApprovalQueue,
} from "../src/host-command.js";

function config(overrides: Partial<EffectiveGuardConfig> = {}): EffectiveGuardConfig {
	return {
		version: 1,
		mode: "strict",
		filesystem: { deny: ["/.env"], workspaceAccess: "read-write" },
		network: { allowedHosts: [], blockInternalRanges: true },
		environment: { allowFromHost: [], values: { HOME: "/root", PATH: "/usr/bin" } },
		hostCommands: {
			"exact-test": {
				description: "Run the exact test command",
				projectRoot: "/project",
				program: "/usr/bin/printf",
				args: ["%s", "hello; $(unsafe)"],
				cwd: "/project",
				timeoutSeconds: 30,
			},
		},
		externalTools: { allow: [] },
		userBash: "sandbox",
		approvalTimeoutSeconds: 60,
		canonicalProjectRoot: "/project",
		sources: { global: "/agent/pi-guard.json" },
		...overrides,
	};
}

function baseOptions(overrides: Record<string, unknown> = {}) {
	const audit: HostCommandAuditEntry[] = [];
	return {
		config: config(),
		ruleId: "exact-test",
		hasUI: true,
		confirm: async () => true,
		exec: async () => ({ stdout: "hello\n", stderr: "", code: 0, killed: false }),
		audit: (entry: HostCommandAuditEntry) => audit.push(entry),
		approvalQueue: new SerializedApprovalQueue(),
		...overrides,
		auditEntries: audit,
	};
}

test("approved host command displays and executes exact program/argv without a shell", async () => {
	let approvalMessage = "";
	let invocation: { program: string; args: string[]; cwd: string } | undefined;
	const audit: HostCommandAuditEntry[] = [];
	const options = baseOptions({
		confirm: async (_title: string, message: string) => {
			approvalMessage = message;
			return true;
		},
		exec: async (program: string, args: string[], execOptions: { cwd: string }) => {
			invocation = { program, args, cwd: execOptions.cwd };
			return { stdout: "hello\n", stderr: "", code: 0, killed: false };
		},
		audit: (entry: HostCommandAuditEntry) => audit.push(entry),
	});
	const result = await executeHostCommand(options);
	assert.deepEqual(invocation, {
		program: "/usr/bin/printf",
		args: ["%s", "hello; $(unsafe)"],
		cwd: "/project",
	});
	assert.match(approvalMessage, /Program: "\/usr\/bin\/printf"/);
	assert.match(approvalMessage, /Argv: \["%s","hello; \$\(unsafe\)"\]/);
	assert.match(approvalMessage, /without a shell/);
	assert.equal(result.details.outcome, "completed");
	assert.deepEqual(audit.map((entry) => entry.outcome), ["approved", "completed"]);
	assert.equal(Object.hasOwn(audit[1] ?? {}, "environment"), false);
});

test("headless, denied, and pre-cancelled approvals fail closed without execution", async () => {
	for (const scenario of [
		{ hasUI: false, confirm: async () => true, outcome: "headless" },
		{ hasUI: true, confirm: async () => false, outcome: "denied" },
		{
			hasUI: true,
			confirm: async () => {
				throw new Error("dialog unavailable");
			},
			outcome: "failed",
		},
	] as const) {
		let executed = false;
		const audit: HostCommandAuditEntry[] = [];
		await assert.rejects(
			executeHostCommand(
				baseOptions({
					hasUI: scenario.hasUI,
					confirm: scenario.confirm,
					exec: async () => {
						executed = true;
						return { stdout: "", stderr: "", code: 0, killed: false };
					},
					audit: (entry: HostCommandAuditEntry) => audit.push(entry),
				}),
			),
			(error) => error instanceof HostCommandBlockedError && error.outcome === scenario.outcome,
		);
		assert.equal(executed, false);
		assert.equal(audit.at(-1)?.outcome, scenario.outcome);
	}

	const controller = new AbortController();
	controller.abort();
	let executed = false;
	await assert.rejects(
		executeHostCommand(
			baseOptions({
				signal: controller.signal,
				exec: async () => {
					executed = true;
					return { stdout: "", stderr: "", code: 0, killed: false };
				},
			}),
		),
		(error) => error instanceof HostCommandBlockedError && error.outcome === "cancelled",
	);
	assert.equal(executed, false);
});

test("approval timeout aborts the dialog and never executes", async () => {
	let executed = false;
	const timedConfig = config({ approvalTimeoutSeconds: 0.01 });
	await assert.rejects(
		executeHostCommand(
			baseOptions({
				config: timedConfig,
				confirm: async (_title: string, _message: string, options: { signal: AbortSignal }) => {
					await new Promise<void>((resolve) => options.signal.addEventListener("abort", () => resolve(), { once: true }));
					return false;
				},
				exec: async () => {
					executed = true;
					return { stdout: "", stderr: "", code: 0, killed: false };
				},
			}),
		),
		(error) => error instanceof HostCommandBlockedError && error.outcome === "approval_timeout",
	);
	assert.equal(executed, false);
});

test("parallel requests serialize approval dialogs", async () => {
	const queue = new SerializedApprovalQueue();
	const resolvers: Array<(approved: boolean) => void> = [];
	let activeDialogs = 0;
	let maximumDialogs = 0;
	const confirm = async () => {
		activeDialogs++;
		maximumDialogs = Math.max(maximumDialogs, activeDialogs);
		try {
			return await new Promise<boolean>((resolve) => resolvers.push(resolve));
		} finally {
			activeDialogs--;
		}
	};
	const first = executeHostCommand(baseOptions({ approvalQueue: queue, confirm }));
	const second = executeHostCommand(baseOptions({ approvalQueue: queue, confirm }));
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(resolvers.length, 1);
	resolvers[0]?.(false);
	await assert.rejects(first);
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(resolvers.length, 2);
	resolvers[1]?.(false);
	await assert.rejects(second);
	assert.equal(maximumDialogs, 1);
});

test("execution timeout aborts the exact process and reports a timed-out result", async () => {
	const rule = { ...config().hostCommands["exact-test"]!, timeoutSeconds: 0.01 };
	const timedConfig = config({ hostCommands: { "exact-test": rule } });
	const audit: HostCommandAuditEntry[] = [];
	const result = await executeHostCommand(
		baseOptions({
			config: timedConfig,
			exec: async (_program: string, _args: string[], options: { signal: AbortSignal }) => {
				await new Promise<void>((resolve) => options.signal.addEventListener("abort", () => resolve(), { once: true }));
				return { stdout: "partial\n", stderr: "", code: 143, killed: true };
			},
			audit: (entry: HostCommandAuditEntry) => audit.push(entry),
		}),
	);
	assert.equal(result.details.outcome, "execution_timeout");
	assert.equal(result.details.killed, true);
	assert.equal(audit.at(-1)?.outcome, "execution_timeout");
});

test("host command output uses Pi's standard truncation limits", async () => {
	const output = `${"line\n".repeat(3_000)}tail-marker\n`;
	const result = await executeHostCommand(baseOptions({ exec: async () => ({ stdout: output, stderr: "", code: 0, killed: false }) }));
	assert.equal(result.details.truncation?.truncated, true);
	assert.match(result.content[0]?.text ?? "", /Output truncated/);
	assert.match(result.content[0]?.text ?? "", /tail-marker/);
});

test("approval display includes all immutable execution metadata", () => {
	const rule = config().hostCommands["exact-test"]!;
	assert.equal(
		formatHostCommandApproval("exact-test", rule),
		[
			"Run the exact test command",
			"",
			"Rule: exact-test",
			'Program: "/usr/bin/printf"',
			'Argv: ["%s","hello; $(unsafe)"]',
			"Cwd: /project",
			"Execution timeout: 30s",
			"",
			"This runs directly on the host without a shell.",
		].join("\n"),
	);
});
