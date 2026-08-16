import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { EffectiveGuardConfig } from "../src/config.js";
import { GuardVmManager } from "../src/gondolin.js";

const liveNetwork = process.env.PI_GUARD_LIVE_TEST === "1" && process.env.PI_GUARD_LIVE_NETWORK_TEST === "1";

test(
	"live Gondolin exact-host and redirect network boundary",
	{ skip: !liveNetwork, timeout: 180_000 },
	async () => {
		const projectRoot = await mkdtemp(path.join(os.tmpdir(), "pi-guard-live-network-"));
		const config: EffectiveGuardConfig = {
			version: 1,
			mode: "strict",
			filesystem: { deny: ["/.env"], workspaceAccess: "read-only" },
			network: { allowedHosts: ["example.com", "httpbin.org"], blockInternalRanges: true },
			environment: {
				allowFromHost: ["LANG", "LC_*", "CI"],
				values: { HOME: "/root", PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
			},
			hostCommands: {},
			externalTools: { allow: [] },
			userBash: "sandbox",
			approvalTimeoutSeconds: 60,
			canonicalProjectRoot: projectRoot,
			sources: { global: path.join(projectRoot, "global-config.json") },
		};
		const manager = new GuardVmManager({ config });
		try {
			const vm = await manager.ensureStarted();
			const clientProbe = await vm.exec(["/bin/sh", "-lc", "command -v curl"], { cwd: "/workspace" });
			assert.equal(clientProbe.exitCode, 0, "guest image must provide curl for network tests");

			const allowed = await vm.exec(
				["/bin/sh", "-lc", "curl -fsS --max-time 15 https://example.com/ >/dev/null"],
				{ cwd: "/workspace" },
			);
			assert.equal(allowed.exitCode, 0, `exact allowed host failed: ${allowed.stderr}`);

			const unlisted = await vm.exec(
				["/bin/sh", "-lc", "curl -fsS --max-time 8 https://www.iana.org/ >/dev/null"],
				{ cwd: "/workspace" },
			);
			assert.notEqual(unlisted.exitCode, 0, "unlisted host unexpectedly succeeded");

			const redirect = await vm.exec(
				[
					"/bin/sh",
					"-lc",
					"curl -LfsS --max-time 15 'https://httpbin.org/redirect-to?url=https%3A%2F%2Fwww.iana.org%2F' >/dev/null",
				],
				{ cwd: "/workspace" },
			);
			assert.notEqual(redirect.exitCode, 0, "redirect to an unlisted host unexpectedly succeeded");

			const metadata = await vm.exec(
				["/bin/sh", "-lc", "curl -fsS --max-time 5 http://169.254.169.254/latest/meta-data/ >/dev/null"],
				{ cwd: "/workspace" },
			);
			assert.notEqual(metadata.exitCode, 0, "metadata address unexpectedly succeeded");
		} finally {
			await manager.close();
			await rm(projectRoot, { recursive: true, force: true });
		}
	},
);
