import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import type { VM } from "@earendil-works/gondolin";
import {
	createGondolinBashOps,
	createGondolinReadOps,
	createGondolinWriteOps,
	hostPathToGuest,
	isInsideHostPath,
	toGuestPath,
} from "../src/tools.js";

const workspace = path.resolve("/tmp/pi-guard-workspace");

test("path conversion maps workspace paths to /workspace consistently", () => {
	assert.equal(toGuestPath(workspace, "."), "/workspace");
	assert.equal(toGuestPath(workspace, "@src/index.ts"), "/workspace/src/index.ts");
	assert.equal(toGuestPath(workspace, path.join(workspace, "src", "index.ts")), "/workspace/src/index.ts");
	assert.equal(hostPathToGuest(workspace, workspace), "/workspace");
	assert.equal(isInsideHostPath(workspace, path.join(workspace, "nested")), true);
	assert.equal(isInsideHostPath(workspace, `${workspace}-evil/token`), false);
});

test("absolute host paths outside the workspace are not remapped into the mount", () => {
	const outside = path.resolve("/tmp/host-secret.txt");
	assert.equal(toGuestPath(workspace, outside), "/tmp/host-secret.txt");
	assert.equal(toGuestPath(workspace, "../../host-secret.txt"), "/host-secret.txt");
});

test("read and write adapters translate every path through the guest workspace", async () => {
	const calls: Array<[string, string]> = [];
	const fakeVm = {
		fs: {
			readFile: async (filePath: string) => {
				calls.push(["read", filePath]);
				return Buffer.from("hello");
			},
			access: async (filePath: string) => {
				calls.push(["access", filePath]);
			},
			writeFile: async (filePath: string) => {
				calls.push(["write", filePath]);
			},
			mkdir: async (filePath: string) => {
				calls.push(["mkdir", filePath]);
			},
		},
	} as unknown as VM;
	const read = createGondolinReadOps(fakeVm, workspace);
	const write = createGondolinWriteOps(fakeVm, workspace);
	await read.readFile("src/a.ts");
	await read.access("@src/a.ts");
	await write.mkdir("src/generated");
	await write.writeFile("src/generated/a.ts", "content");
	assert.deepEqual(calls, [
		["read", "/workspace/src/a.ts"],
		["access", "/workspace/src/a.ts"],
		["mkdir", "/workspace/src/generated"],
		["write", "/workspace/src/generated/a.ts"],
	]);
});

test("Bash adapter streams output while filtering host environment", async () => {
	let invocation:
		| { argv: string[]; options: { cwd?: string; env?: Record<string, string>; signal?: AbortSignal } }
		| undefined;
	const processResult = Object.assign(Promise.resolve({ exitCode: 0 }), {
		async *output() {
			yield { data: Buffer.from("ok\n") };
		},
	});
	const fakeVm = {
		exec(argv: string[], options: { cwd?: string; env?: Record<string, string>; signal?: AbortSignal }) {
			invocation = { argv, options };
			return processResult;
		},
	} as unknown as VM;
	const chunks: string[] = [];
	const operations = createGondolinBashOps(fakeVm, workspace, "/bin/bash", {
		allowFromHost: ["LANG", "LC_*"],
		values: { HOME: "/root", PATH: "/usr/bin" },
	});
	const result = await operations.exec("printf ok", workspace, {
		onData: (data) => chunks.push(data.toString("utf8")),
		env: {
			LANG: "C",
			LC_ALL: "C",
			SECRET_TOKEN: "must-not-cross",
			SSH_AUTH_SOCK: "/tmp/agent.sock",
			PATH: "/host/bin",
		},
	});
	assert.deepEqual(result, { exitCode: 0 });
	assert.deepEqual(chunks, ["ok\n"]);
	assert.deepEqual(invocation?.argv, ["/bin/bash", "-lc", "printf ok"]);
	assert.equal(invocation?.options.cwd, "/workspace");
	assert.deepEqual(invocation?.options.env, {
		LANG: "C",
		LC_ALL: "C",
		HOME: "/root",
		PATH: "/usr/bin",
	});
});

test("Bash adapter honors an already-aborted signal without starting a process", async () => {
	let called = false;
	const fakeVm = {
		exec() {
			called = true;
			throw new Error("must not execute");
		},
	} as unknown as VM;
	const controller = new AbortController();
	controller.abort();
	const operations = createGondolinBashOps(fakeVm, workspace, "/bin/sh", {
		allowFromHost: [],
		values: { HOME: "/root", PATH: "/usr/bin" },
	});
	await assert.rejects(
		operations.exec("echo unsafe", workspace, {
			onData: () => undefined,
			signal: controller.signal,
		}),
		/aborted/,
	);
	assert.equal(called, false);
});
