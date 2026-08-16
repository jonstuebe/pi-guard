import { getAssetDirectory } from "@earendil-works/gondolin";
import { mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import type { EffectiveGuardConfig } from "../src/config.js";
import { GuardVmManager } from "../src/gondolin.js";

async function directoryBytes(root: string): Promise<number> {
	let total = 0;
	const visit = async (entryPath: string): Promise<void> => {
		let metadata;
		try {
			metadata = await stat(entryPath);
		} catch {
			return;
		}
		if (!metadata.isDirectory()) {
			total += metadata.size;
			return;
		}
		for (const entry of await readdir(entryPath)) await visit(path.join(entryPath, entry));
	};
	await visit(root);
	return total;
}

function percentile(values: number[], fraction: number): number {
	const sorted = [...values].sort((left, right) => left - right);
	return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1))] ?? 0;
}

const projectRoot = await mkdtemp(path.join(os.tmpdir(), "pi-guard-benchmark-"));
const config: EffectiveGuardConfig = {
	version: 1,
	mode: "strict",
	filesystem: { deny: ["/.env", "/.env.*", "/*.pem", "/*.key", "/secrets/**"], workspaceAccess: "read-write" },
	network: { allowedHosts: [], blockInternalRanges: true },
	environment: {
		allowFromHost: ["LANG", "LC_*", "TERM", "CI"],
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
const rssBefore = process.memoryUsage().rss;
try {
	const start = performance.now();
	const vm = await manager.ensureStarted();
	const coldStartMs = performance.now() - start;
	const rssReady = process.memoryUsage().rss;
	const warmSamplesMs: number[] = [];
	for (let index = 0; index < 20; index++) {
		const commandStart = performance.now();
		const result = await vm.exec(["/bin/sh", "-lc", "printf benchmark"], { cwd: "/workspace" });
		if (result.exitCode !== 0 || result.stdout !== "benchmark") throw new Error("benchmark guest command failed");
		warmSamplesMs.push(performance.now() - commandStart);
	}
	const assetDirectory = getAssetDirectory();
	const report = {
		schemaVersion: 1,
		timestamp: new Date().toISOString(),
		platform: process.platform,
		architecture: process.arch,
		nodeVersion: process.versions.node,
		gondolinVersion: "0.12.0",
		iterations: warmSamplesMs.length,
		coldVmStartMs: Number(coldStartMs.toFixed(2)),
		warmCommandMs: {
			median: Number(percentile(warmSamplesMs, 0.5).toFixed(2)),
			p95: Number(percentile(warmSamplesMs, 0.95).toFixed(2)),
			minimum: Number(Math.min(...warmSamplesMs).toFixed(2)),
			maximum: Number(Math.max(...warmSamplesMs).toFixed(2)),
		},
		hostRssDeltaBytesAtReady: Math.max(0, rssReady - rssBefore),
		assetDirectory,
		assetDiskBytes: await directoryBytes(assetDirectory),
	};
	const output = `${JSON.stringify(report, null, 2)}\n`;
	if (process.env.PI_GUARD_BENCH_OUTPUT) {
		await writeFile(path.resolve(process.env.PI_GUARD_BENCH_OUTPUT), output, "utf8");
	}
	process.stdout.write(output);
} finally {
	await manager.close();
	await rm(projectRoot, { recursive: true, force: true });
}
