import { constants } from "node:fs";
import { access } from "node:fs/promises";
import path from "node:path";
import { getAssetDirectory, hasGuestAssets } from "@earendil-works/gondolin";
import type { EffectiveGuardConfig } from "./config.js";
import type { GuardVmSnapshot } from "./gondolin.js";

export interface DiagnosticCheck {
	name: string;
	ok: boolean;
	detail: string;
}

export async function findExecutable(names: readonly string[], environmentPath = process.env.PATH ?? ""): Promise<string | undefined> {
	for (const directory of environmentPath.split(path.delimiter)) {
		if (!directory) continue;
		for (const name of names) {
			const candidate = path.join(directory, name);
			try {
				await access(candidate, constants.X_OK);
				return candidate;
			} catch {
				// Continue searching PATH.
			}
		}
	}
	return undefined;
}

export function nodeVersionSupported(version: string): boolean {
	const [major = 0, minor = 0] = version.split(".").map(Number);
	return major > 23 || (major === 23 && minor >= 6);
}

export interface DiagnosticOptions {
	environmentPath?: string;
	nodeVersion?: string;
	platform?: NodeJS.Platform;
	assetsAvailable?: boolean;
	assetDirectory?: string;
}

export async function runDiagnostics(
	config: EffectiveGuardConfig,
	vm: GuardVmSnapshot,
	options: DiagnosticOptions = {},
): Promise<DiagnosticCheck[]> {
	const nodeVersion = options.nodeVersion ?? process.versions.node;
	const platform = options.platform ?? process.platform;
	const qemu = await findExecutable(
		["qemu-system-aarch64", "qemu-system-x86_64"],
		options.environmentPath ?? process.env.PATH ?? "",
	);
	const assetsAvailable = options.assetsAvailable ?? hasGuestAssets();
	const assetDirectory = options.assetDirectory ?? getAssetDirectory();
	const runtimeRequired = config.mode !== "disabled";
	return [
		{
			name: "Platform",
			ok: platform === "darwin" || platform === "linux",
			detail: `${platform} (supported: macOS and Linux)`,
		},
		{
			name: "Node.js",
			ok: nodeVersionSupported(nodeVersion),
			detail: `${nodeVersion} (requires >=23.6.0)`,
		},
		{
			name: "QEMU",
			ok: !runtimeRequired || qemu !== undefined,
			detail: runtimeRequired ? (qemu ?? "not found on PATH") : "not required while disabled",
		},
		{
			name: "Guest assets",
			ok: !runtimeRequired || assetsAvailable,
			detail: runtimeRequired
				? assetsAvailable
					? assetDirectory
					: `not initialized (${assetDirectory}); start a guarded session to download them`
				: "not required while disabled",
		},
		{
			name: "Configuration",
			ok: true,
			detail: `${config.mode}; global=${config.sources.global}${config.sources.project ? `; project=${config.sources.project}` : ""}`,
		},
		{
			name: "Network",
			ok: config.network.blockInternalRanges,
			detail: `${
				config.network.allowedHosts.length === 0
					? "deny-all"
					: `allowed hosts: ${config.network.allowedHosts.join(", ")}`
			}; internal ranges ${config.network.blockInternalRanges ? "blocked" : "allowed"}`,
		},
		{
			name: "VM",
			ok: !runtimeRequired || vm.state === "ready",
			detail:
				!runtimeRequired
					? "not required while disabled"
					: vm.state === "ready"
						? `${vm.vmId ?? "ready"}; shell=${vm.shellPath ?? "unknown"}`
						: vm.error
							? `${vm.state}: ${vm.error.message}`
							: vm.state,
		},
	];
}

export function formatDiagnostics(checks: readonly DiagnosticCheck[]): string {
	return checks.map((check) => `${check.ok ? "✓" : "✗"} ${check.name}: ${check.detail}`).join("\n");
}
