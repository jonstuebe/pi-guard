import path from "node:path";
import type { EnvironmentPolicy } from "./config.js";

function normalizeVfsPath(value: string): string {
	const prefixed = value.startsWith("/") ? value : `/${value}`;
	return path.posix.normalize(prefixed);
}

function hasGlob(pattern: string): boolean {
	return /[*?\[\]{}]/.test(pattern);
}

export function createDeniedPathPredicate(patterns: readonly string[]): (context: { path: string }) => boolean {
	const normalizedPatterns = patterns.map(normalizeVfsPath);
	return ({ path: candidate }) => {
		const normalizedCandidate = normalizeVfsPath(candidate);
		return normalizedPatterns.some((pattern) => {
			if (!hasGlob(pattern)) return normalizedCandidate === pattern || normalizedCandidate.startsWith(`${pattern}/`);
			if (pattern.endsWith("/**") && normalizedCandidate === pattern.slice(0, -3)) return true;
			return path.posix.matchesGlob(normalizedCandidate, pattern);
		});
	};
}

function matchesEnvironmentPattern(name: string, pattern: string): boolean {
	if (pattern.endsWith("*")) return name.startsWith(pattern.slice(0, -1));
	return name === pattern;
}

export function buildGuestEnvironment(
	policy: EnvironmentPolicy,
	hostEnvironment: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
	const guest: Record<string, string> = {};
	for (const [name, value] of Object.entries(hostEnvironment)) {
		if (typeof value !== "string") continue;
		if (policy.allowFromHost.some((pattern) => matchesEnvironmentPattern(name, pattern))) guest[name] = value;
	}
	return { ...guest, ...policy.values };
}
