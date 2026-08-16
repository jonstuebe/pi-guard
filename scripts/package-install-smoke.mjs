import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const projectRoot = path.resolve(import.meta.dirname, "..");
const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "pi-guard-install-smoke-"));
const agentDir = path.join(temporaryRoot, "agent");
const piBinary = path.join(projectRoot, "node_modules", ".bin", process.platform === "win32" ? "pi.cmd" : "pi");
const environment = {
	...process.env,
	PI_CODING_AGENT_DIR: agentDir,
	PI_OFFLINE: "1",
	PI_SKIP_VERSION_CHECK: "1",
	PI_TELEMETRY: "0",
};

async function run(command, args, options = {}) {
	return exec(command, args, {
		cwd: projectRoot,
		env: environment,
		timeout: 180_000,
		maxBuffer: 10 * 1024 * 1024,
		...options,
	});
}

try {
	const packed = await run("npm", ["pack", "--json", "--pack-destination", temporaryRoot]);
	const packResult = JSON.parse(packed.stdout);
	assert.equal(Array.isArray(packResult), true, "npm pack did not return an array");
	const tarball = path.join(temporaryRoot, packResult[0]?.filename ?? "");
	await run("tar", ["-xzf", tarball, "-C", temporaryRoot]);
	const packageDir = path.join(temporaryRoot, "package");
	await run(
		"npm",
		["install", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"],
		{ cwd: packageDir },
	);
	await readFile(path.join(packageDir, "node_modules", "@earendil-works", "gondolin", "package.json"), "utf8");

	await run(piBinary, ["install", packageDir]);
	const listed = await run(piBinary, ["list"]);
	assert.match(listed.stdout, /pi-guard|install-smoke-[^\s/]+\/package/);
	await run(piBinary, ["--list-models"]);

	const settings = JSON.parse(await readFile(path.join(agentDir, "settings.json"), "utf8"));
	assert.equal(Array.isArray(settings.packages), true);
	const recordedSources = settings.packages.map((entry) =>
		typeof entry === "string" ? entry : typeof entry?.source === "string" ? entry.source : "",
	);
	assert.equal(
		recordedSources.some(
			(source) => source === packageDir || path.resolve(agentDir, source) === packageDir || source.includes(path.basename(temporaryRoot)),
		),
		true,
		`Pi settings did not record the staged package source: ${JSON.stringify(recordedSources)}`,
	);
	console.log("package-install-smoke: passed");
	console.log(`staged package: ${packageDir}`);
	console.log("verified: npm tarball, production dependencies, pi install, extension load, pi list, isolated settings");
} finally {
	await rm(temporaryRoot, { recursive: true, force: true });
}
