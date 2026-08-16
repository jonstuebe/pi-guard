import assert from "node:assert/strict";
import { mkdtemp, mkdir, realpath, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
	DEFAULT_DENIED_VFS_PATTERNS,
	GuardConfigError,
	loadEffectiveConfig,
	parseGlobalConfig,
	parseProjectConfig,
} from "../src/config.js";

async function fixture(): Promise<{ root: string; agent: string }> {
	const root = await mkdtemp(path.join(os.tmpdir(), "pi-guard-test-"));
	const agent = path.join(root, "agent");
	await mkdir(agent);
	return { root: await realpath(root), agent };
}

test("zero-config policy is strict, deny-all, and secret-safe", async () => {
	const { root, agent } = await fixture();
	const config = await loadEffectiveConfig({
		agentDir: agent,
		projectRoot: root,
		projectConfigDirName: ".pi",
		projectTrusted: false,
	});
	assert.equal(config.mode, "strict");
	assert.deepEqual(config.network.allowedHosts, []);
	assert.deepEqual(config.externalTools.allow, []);
	assert.equal(config.environment.allowFromHost.includes("PATH"), false);
	assert.equal(config.environment.values.PATH?.startsWith("/usr/local"), true);
	for (const denied of DEFAULT_DENIED_VFS_PATTERNS) assert.equal(config.filesystem.deny.includes(denied), true);
});

test("project config may tighten filesystem and network policy", async () => {
	const { root, agent } = await fixture();
	await writeFile(
		path.join(agent, "pi-guard.json"),
		JSON.stringify({ version: 1, network: { allowedHosts: ["api.github.com"] } }),
	);
	await mkdir(path.join(root, ".pi"));
	await writeFile(
		path.join(root, ".pi", "pi-guard.json"),
		JSON.stringify({
			version: 1,
			filesystem: { deny: ["/private-fixtures/**"], workspaceAccess: "read-only" },
			network: { allowedHosts: [] },
		}),
	);
	const config = await loadEffectiveConfig({
		agentDir: agent,
		projectRoot: root,
		projectConfigDirName: ".pi",
		projectTrusted: true,
	});
	assert.equal(config.filesystem.workspaceAccess, "read-only");
	assert.equal(config.filesystem.deny.includes("/private-fixtures/**"), true);
	assert.deepEqual(config.network.allowedHosts, []);
	assert.equal(config.sources.project, path.join(root, ".pi", "pi-guard.json"));
});

test("untrusted project config is ignored", async () => {
	const { root, agent } = await fixture();
	await mkdir(path.join(root, ".pi"));
	await writeFile(path.join(root, ".pi", "pi-guard.json"), "not json");
	const config = await loadEffectiveConfig({
		agentDir: agent,
		projectRoot: root,
		projectConfigDirName: ".pi",
		projectTrusted: false,
	});
	assert.equal(config.sources.project, undefined);
});

test("project cannot broaden the global network ceiling", async () => {
	const { root, agent } = await fixture();
	await mkdir(path.join(root, ".pi"));
	await writeFile(
		path.join(root, ".pi", "pi-guard.json"),
		JSON.stringify({ version: 1, network: { allowedHosts: ["attacker.example"] } }),
	);
	await assert.rejects(
		loadEffectiveConfig({
			agentDir: agent,
			projectRoot: root,
			projectConfigDirName: ".pi",
			projectTrusted: true,
		}),
		GuardConfigError,
	);
});

test("unknown and trust-expanding project keys fail validation", () => {
	assert.throws(() => parseProjectConfig({ version: 1, hostCommands: {} }), GuardConfigError);
	assert.throws(() => parseGlobalConfig({ version: 1, typo: true }), GuardConfigError);
});

test("host commands are exact, global-only rules scoped to canonical project", async () => {
	const { root, agent } = await fixture();
	await writeFile(
		path.join(agent, "pi-guard.json"),
		JSON.stringify({
			version: 1,
			hostCommands: {
				"run-tests": {
					description: "Run tests",
					projectRoot: root,
					program: "npm",
					args: ["test"],
					cwd: root,
				},
			},
		}),
	);
	const config = await loadEffectiveConfig({
		agentDir: agent,
		projectRoot: root,
		projectConfigDirName: ".pi",
		projectTrusted: false,
	});
	assert.deepEqual(config.hostCommands["run-tests"]?.args, ["test"]);
	assert.equal(config.hostCommands["run-tests"]?.projectRoot, root);
});
