import { VM } from "@earendil-works/gondolin";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { EffectiveGuardConfig } from "../src/config.js";
import { GuardVmManager } from "../src/gondolin.js";
import {
	createGondolinFindOps,
	createGondolinLsOps,
	createGondolinReadOps,
	executeGondolinGrep,
} from "../src/tools.js";

const live = process.env.PI_GUARD_LIVE_TEST === "1";

function createLiveManager(config: EffectiveGuardConfig): GuardVmManager {
	const accel = process.env.PI_GUARD_QEMU_ACCEL;
	return new GuardVmManager({
		config,
		...(accel
			? { createVm: (options) => VM.create({ ...options, sandbox: { ...options?.sandbox, accel } }) }
			: {}),
	});
}

test(
	"live Gondolin security boundary",
	{ skip: !live, timeout: 180_000 },
	async () => {
		const projectRoot = await mkdtemp(path.join(os.tmpdir(), "pi-guard-live-project-"));
		const outsideRoot = await mkdtemp(path.join(os.tmpdir(), "pi-guard-live-outside-"));
		const outsideSecret = path.join(outsideRoot, "outside-secret.txt");
		await writeFile(path.join(projectRoot, "public.txt"), "public-data\n");
		await writeFile(path.join(projectRoot, ".env"), "SECRET_TOKEN=workspace-secret\n");
		await writeFile(outsideSecret, "outside-secret\n");
		await symlink(".env", path.join(projectRoot, "secret-link"));
		await symlink(outsideSecret, path.join(projectRoot, "outside-link"));
		await symlink("missing-target", path.join(projectRoot, "dangling-link"));

		const config: EffectiveGuardConfig = {
			version: 1,
			mode: "strict",
			filesystem: {
				deny: ["/.env", "/.env.*", "/*.pem", "/*.key", "/secrets/**", "/credentials/**"],
				workspaceAccess: "read-write",
			},
			network: { allowedHosts: [], blockInternalRanges: true },
			environment: {
				allowFromHost: ["LANG", "LC_*", "TERM", "CI"],
				values: {
					HOME: "/root",
					PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				},
			},
			hostCommands: {},
			externalTools: { allow: [] },
			userBash: "sandbox",
			approvalTimeoutSeconds: 60,
			canonicalProjectRoot: projectRoot,
			sources: { global: path.join(outsideRoot, "pi-guard.json") },
		};

		const previousSecret = process.env.PI_GUARD_LIVE_SECRET;
		process.env.PI_GUARD_LIVE_SECRET = "must-not-enter-guest";
		const manager = createLiveManager(config);
		let readonlyManager: GuardVmManager | undefined;
		try {
			const vm = await manager.ensureStarted();
			assert.equal(manager.snapshot.state, "ready");

			assert.equal((await vm.fs.readFile("/workspace/public.txt", { encoding: "utf8" })).trim(), "public-data");
			const entries = await vm.fs.listDir("/workspace");
			assert.equal(entries.includes("public.txt"), true);
			assert.equal(entries.includes(".env"), false);
			await assert.rejects(vm.fs.access("/workspace/.env"));
			await assert.rejects(vm.fs.readFile("/workspace/secret-link", { encoding: "utf8" }));
			await assert.rejects(vm.fs.readFile("/workspace/outside-link", { encoding: "utf8" }));
			await assert.rejects(vm.fs.readFile("/workspace/dangling-link", { encoding: "utf8" }));

			const readOps = createGondolinReadOps(vm, projectRoot);
			const lsOps = createGondolinLsOps(vm, projectRoot);
			const findOps = createGondolinFindOps(vm, projectRoot);
			await assert.rejects(readOps.readFile(".env"));
			assert.equal((await lsOps.readdir(".")).includes(".env"), false);
			assert.equal((await findOps.glob("*", ".", { ignore: [], limit: 100 })).some((entry) => entry.endsWith("/.env")), false);
			const grep = await executeGondolinGrep(vm, projectRoot, { pattern: "workspace-secret", path: "." });
			assert.equal(grep.content[0]?.text, "No matches found");

			await vm.fs.writeFile("/workspace/generated.txt", "persisted\n", { encoding: "utf8" });
			assert.equal((await readFile(path.join(projectRoot, "generated.txt"), "utf8")).trim(), "persisted");

			const environment = await vm.exec(
				[
					"/bin/sh",
					"-lc",
					"printf '%s\\n%s\\n%s\\n%s\\n%s' \"$HOME\" \"$PATH\" \"${PI_GUARD_LIVE_SECRET-unset}\" \"${SSH_AUTH_SOCK-unset}\" \"${PI_SESSION_FILE-unset}\"",
				],
				{ cwd: "/workspace" },
			);
			assert.equal(environment.exitCode, 0);
			assert.deepEqual(environment.stdout.trim().split("\n"), [
				"/root",
				"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"unset",
				"unset",
				"unset",
			]);

			const shellBoundary = await vm.exec(
				[
					"/bin/sh",
					"-lc",
					`set -eu; printf '%s' "$(printf guest)-pipeline" | tr a-z A-Z > /workspace/shell-generated.txt; ! cat ${JSON.stringify(outsideSecret)}; ! cat /workspace/.env`,
				],
				{ cwd: "/workspace" },
			);
			assert.equal(shellBoundary.exitCode, 0);
			assert.equal((await readFile(path.join(projectRoot, "shell-generated.txt"), "utf8")).trim(), "GUEST-PIPELINE");

			const clientProbe = await vm.exec(["/bin/sh", "-lc", "command -v curl || command -v wget"], { cwd: "/workspace" });
			assert.equal(clientProbe.exitCode, 0, "guest image must provide curl or wget for the deny-all network test");
			const network = await vm.exec(
				[
					"/bin/sh",
					"-lc",
					"if command -v curl >/dev/null; then curl -fsS --max-time 5 http://example.com/; else wget -qO- -T 5 http://example.com/; fi",
				],
				{ cwd: "/workspace" },
			);
			assert.notEqual(network.exitCode, 0, "deny-all networking unexpectedly allowed example.com");
			const internalNetwork = await vm.exec(
				[
					"/bin/sh",
					"-lc",
					"if command -v curl >/dev/null; then curl -fsS --max-time 3 http://127.0.0.1/; else wget -qO- -T 3 http://127.0.0.1/; fi",
				],
				{ cwd: "/workspace" },
			);
			assert.notEqual(internalNetwork.exitCode, 0, "internal networking unexpectedly allowed localhost");

			await manager.close();
			readonlyManager = createLiveManager({
				...config,
				filesystem: { ...config.filesystem, workspaceAccess: "read-only" },
			});
			const readonlyVm = await readonlyManager.ensureStarted();
			assert.equal((await readonlyVm.fs.readFile("/workspace/public.txt", { encoding: "utf8" })).trim(), "public-data");
			await assert.rejects(readonlyVm.fs.writeFile("/workspace/must-not-persist.txt", "blocked\n", { encoding: "utf8" }));
			await assert.rejects(readFile(path.join(projectRoot, "must-not-persist.txt"), "utf8"));
		} finally {
			await readonlyManager?.close();
			await manager.close();
			if (previousSecret === undefined) delete process.env.PI_GUARD_LIVE_SECRET;
			else process.env.PI_GUARD_LIVE_SECRET = previousSecret;
			await rm(projectRoot, { recursive: true, force: true });
			await rm(outsideRoot, { recursive: true, force: true });
		}
	},
);
