import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { VM } from "@earendil-works/gondolin";
import type { EffectiveGuardConfig } from "../src/config.js";
import { findExecutable, nodeVersionSupported, runDiagnostics } from "../src/diagnostics.js";
import { GuardVmManager } from "../src/gondolin.js";
import { createGondolinBashOps } from "../src/tools.js";

function testConfig(overrides: Partial<EffectiveGuardConfig> = {}): EffectiveGuardConfig {
	return {
		version: 1,
		mode: "strict",
		filesystem: { deny: ["/.env"], workspaceAccess: "read-write" },
		network: { allowedHosts: [], blockInternalRanges: true },
		environment: { allowFromHost: [], values: { HOME: "/root", PATH: "/usr/bin" } },
		hostCommands: {},
		externalTools: { allow: [] },
		userBash: "sandbox",
		approvalTimeoutSeconds: 60,
		canonicalProjectRoot: path.resolve("/tmp/pi-guard-hardening"),
		sources: { global: path.resolve("/tmp/pi-guard.json") },
		...overrides,
	};
}

function abortingProcess(signal: AbortSignal, errorMessage: string) {
	const result = Object.assign(
		new Promise<{ exitCode: number }>((resolve) => {
			signal.addEventListener("abort", () => resolve({ exitCode: 143 }), { once: true });
		}),
		{
			async *output() {
				await new Promise<void>((_resolve, reject) => {
					signal.addEventListener("abort", () => reject(new Error(errorMessage)), { once: true });
				});
			},
		},
	);
	return result;
}

test("VM creation failure enters blocked state and never retries through another backend", async () => {
	let createCalls = 0;
	const states: string[] = [];
	const manager = new GuardVmManager({
		config: testConfig(),
		createVm: async () => {
			createCalls++;
			throw new Error("injected VM startup failure");
		},
		onStateChange: (snapshot) => states.push(snapshot.state),
	});
	await assert.rejects(manager.ensureStarted(), /injected VM startup failure/);
	assert.equal(createCalls, 1);
	assert.equal(manager.snapshot.state, "blocked");
	assert.match(manager.snapshot.error?.message ?? "", /injected VM startup failure/);
	assert.deepEqual(states, ["starting", "blocked"]);
	await manager.close();
	assert.equal(manager.snapshot.state, "stopped");
});

test("concurrent VM startup is deduplicated", async () => {
	let createCalls = 0;
	let closeCalls = 0;
	const fakeVm = {
		id: "injected-vm",
		exec: async () => ({ stdout: "/bin/sh\n", exitCode: 0 }),
		close: async () => {
			closeCalls++;
		},
	} as unknown as VM;
	const manager = new GuardVmManager({
		config: testConfig(),
		createVm: async () => {
			createCalls++;
			await new Promise((resolve) => setTimeout(resolve, 5));
			return fakeVm;
		},
	});
	const [first, second] = await Promise.all([manager.ensureStarted(), manager.ensureStarted()]);
	assert.equal(first, fakeVm);
	assert.equal(second, fakeVm);
	assert.equal(createCalls, 1);
	await manager.close();
	assert.equal(closeCalls, 1);
});

test("a VM that fails its shell probe is closed and blocked", async () => {
	let closeCalls = 0;
	const fakeVm = {
		id: "probe-failure-vm",
		exec: async () => {
			throw new Error("injected probe failure");
		},
		close: async () => {
			closeCalls++;
		},
	} as unknown as VM;
	const manager = new GuardVmManager({ config: testConfig(), createVm: async () => fakeVm });
	await assert.rejects(manager.ensureStarted(), /injected probe failure/);
	assert.equal(closeCalls, 1);
	assert.equal(manager.snapshot.state, "blocked");
});

test("active Bash cancellation aborts the guest process", async () => {
	let guestSignal: AbortSignal | undefined;
	const fakeVm = {
		exec(_argv: string[], options: { signal: AbortSignal }) {
			guestSignal = options.signal;
			return abortingProcess(options.signal, "guest cancelled");
		},
	} as unknown as VM;
	const controller = new AbortController();
	const operations = createGondolinBashOps(fakeVm, testConfig().canonicalProjectRoot, "/bin/sh", testConfig().environment);
	const execution = operations.exec("sleep 30", testConfig().canonicalProjectRoot, {
		onData: () => undefined,
		signal: controller.signal,
	});
	await new Promise((resolve) => setImmediate(resolve));
	controller.abort();
	await assert.rejects(execution, /^Error: aborted$/);
	assert.equal(guestSignal?.aborted, true);
});

test("Bash timeout aborts the guest process without host fallback", async () => {
	let calls = 0;
	let guestSignal: AbortSignal | undefined;
	const fakeVm = {
		exec(_argv: string[], options: { signal: AbortSignal }) {
			calls++;
			guestSignal = options.signal;
			return abortingProcess(options.signal, "guest timeout");
		},
	} as unknown as VM;
	const operations = createGondolinBashOps(fakeVm, testConfig().canonicalProjectRoot, "/bin/sh", testConfig().environment);
	await assert.rejects(
		operations.exec("sleep 30", testConfig().canonicalProjectRoot, {
			onData: () => undefined,
			timeout: 0.01,
		}),
		/^Error: timeout:0.01$/,
	);
	assert.equal(calls, 1);
	assert.equal(guestSignal?.aborted, true);
});

test("diagnostics validate versions, executable permission, assets, platform, and explicit network posture", async () => {
	assert.equal(nodeVersionSupported("23.5.9"), false);
	assert.equal(nodeVersionSupported("23.6.0"), true);
	assert.equal(nodeVersionSupported("24.0.0"), true);

	const directory = await mkdtemp(path.join(os.tmpdir(), "pi-guard-diagnostics-"));
	const qemu = path.join(directory, "qemu-system-x86_64");
	try {
		await writeFile(qemu, "#!/bin/sh\nexit 0\n");
		await chmod(qemu, 0o644);
		assert.equal(await findExecutable(["qemu-system-x86_64"], directory), undefined);
		await chmod(qemu, 0o755);
		assert.equal(await findExecutable(["qemu-system-x86_64"], directory), qemu);

		const checks = await runDiagnostics(testConfig(), { state: "ready", vmId: "test", shellPath: "/bin/sh" }, {
			environmentPath: directory,
			nodeVersion: "24.0.0",
			platform: "linux",
			assetsAvailable: true,
			assetDirectory: "/cache/gondolin",
		});
		assert.equal(checks.every((check) => check.ok), true);
		assert.match(checks.find((check) => check.name === "Network")?.detail ?? "", /deny-all; internal ranges blocked/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});
