import { readFile, realpath } from "node:fs/promises";
import path from "node:path";

export const CONFIG_VERSION = 1 as const;
export const GLOBAL_CONFIG_FILENAME = "pi-guard.json";
export const PROJECT_CONFIG_FILENAME = "pi-guard.json";

export type GuardMode = "strict" | "compatible" | "disabled";
export type WorkspaceAccess = "read-write" | "read-only";
export type UserBashMode = "sandbox" | "host" | "blocked";

export interface FilesystemPolicy {
	deny: string[];
	workspaceAccess: WorkspaceAccess;
}

export interface NetworkPolicy {
	allowedHosts: string[];
	blockInternalRanges: boolean;
}

export interface EnvironmentPolicy {
	allowFromHost: string[];
	values: Record<string, string>;
}

export interface HostCommandRule {
	description: string;
	projectRoot: string;
	program: string;
	args: string[];
	cwd: string;
	timeoutSeconds: number;
}

export interface EffectiveGuardConfig {
	version: typeof CONFIG_VERSION;
	mode: GuardMode;
	filesystem: FilesystemPolicy;
	network: NetworkPolicy;
	environment: EnvironmentPolicy;
	hostCommands: Record<string, HostCommandRule>;
	externalTools: { allow: string[] };
	userBash: UserBashMode;
	approvalTimeoutSeconds: number;
	canonicalProjectRoot: string;
	sources: {
		global: string;
		project?: string;
	};
}

interface GlobalGuardConfig {
	version: typeof CONFIG_VERSION;
	mode: GuardMode;
	filesystem: FilesystemPolicy;
	network: NetworkPolicy;
	environment: EnvironmentPolicy;
	hostCommands: Record<string, HostCommandRule>;
	externalTools: { allow: string[] };
	userBash: UserBashMode;
	approvalTimeoutSeconds: number;
}

interface ProjectGuardConfig {
	version: typeof CONFIG_VERSION;
	filesystem?: Partial<FilesystemPolicy>;
	network?: { allowedHosts?: string[] };
}

export interface LoadConfigOptions {
	agentDir: string;
	projectRoot: string;
	projectConfigDirName: string;
	projectTrusted: boolean;
}

export const DEFAULT_DENIED_VFS_PATTERNS = [
	"/.env",
	"/.env.*",
	"/.npmrc",
	"/.pypirc",
	"/*.pem",
	"/*.key",
	"/secrets/**",
	"/credentials/**",
] as const;

const DEFAULT_GLOBAL_CONFIG: GlobalGuardConfig = {
	version: CONFIG_VERSION,
	mode: "strict",
	filesystem: {
		deny: [...DEFAULT_DENIED_VFS_PATTERNS],
		workspaceAccess: "read-write",
	},
	network: {
		allowedHosts: [],
		blockInternalRanges: true,
	},
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
};

export class GuardConfigError extends Error {
	readonly configPath: string | undefined;

	constructor(message: string, configPath?: string, options?: ErrorOptions) {
		super(configPath ? `${configPath}: ${message}` : message, options);
		this.name = "GuardConfigError";
		this.configPath = configPath;
	}
}

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function objectAt(value: unknown, label: string): JsonObject {
	if (!isObject(value)) throw new GuardConfigError(`${label} must be an object`);
	return value;
}

function rejectUnknownKeys(value: JsonObject, allowed: readonly string[], label: string): void {
	const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
	if (unknown.length > 0) throw new GuardConfigError(`${label} contains unknown key(s): ${unknown.join(", ")}`);
}

function stringAt(value: unknown, label: string): string {
	if (typeof value !== "string" || value.length === 0) throw new GuardConfigError(`${label} must be a non-empty string`);
	if (value.includes("\0")) throw new GuardConfigError(`${label} must not contain NUL bytes`);
	return value;
}

function stringArrayAt(value: unknown, label: string): string[] {
	if (!Array.isArray(value)) throw new GuardConfigError(`${label} must be an array`);
	return value.map((entry, index) => stringAt(entry, `${label}[${index}]`));
}

function booleanAt(value: unknown, label: string): boolean {
	if (typeof value !== "boolean") throw new GuardConfigError(`${label} must be a boolean`);
	return value;
}

function positiveIntegerAt(value: unknown, label: string): number {
	if (!Number.isSafeInteger(value) || (value as number) <= 0) {
		throw new GuardConfigError(`${label} must be a positive integer`);
	}
	return value as number;
}

function enumAt<T extends string>(value: unknown, allowed: readonly T[], label: string): T {
	if (typeof value !== "string" || !allowed.includes(value as T)) {
		throw new GuardConfigError(`${label} must be one of: ${allowed.join(", ")}`);
	}
	return value as T;
}

function deduplicate(values: readonly string[]): string[] {
	return [...new Set(values)];
}

function normalizeDenyPattern(value: string, label: string): string {
	if (value.includes("\\")) throw new GuardConfigError(`${label} must use POSIX '/' separators`);
	const prefixed = value.startsWith("/") ? value : `/${value}`;
	const segments = prefixed.split("/");
	if (segments.includes("..")) throw new GuardConfigError(`${label} must not contain '..' segments`);
	return path.posix.normalize(prefixed);
}

function parseDenyPatterns(value: unknown, label: string): string[] {
	return deduplicate(stringArrayAt(value, label).map((entry, index) => normalizeDenyPattern(entry, `${label}[${index}]`)));
}

function parseAllowedHosts(value: unknown, label: string): string[] {
	return deduplicate(
		stringArrayAt(value, label).map((host, index) => {
			const normalized = host.trim().toLowerCase();
			if (!normalized || normalized.includes("://") || normalized.includes("/") || /\s/.test(normalized)) {
				throw new GuardConfigError(`${label}[${index}] must be a hostname or wildcard hostname`);
			}
			return normalized;
		}),
	);
}

function parseStringRecord(value: unknown, label: string): Record<string, string> {
	const input = objectAt(value, label);
	const output: Record<string, string> = {};
	for (const [key, entry] of Object.entries(input)) {
		if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new GuardConfigError(`${label}.${key} is not a valid environment name`);
		output[key] = stringAt(entry, `${label}.${key}`);
	}
	return output;
}

function parseHostCommand(value: unknown, label: string): HostCommandRule {
	const input = objectAt(value, label);
	rejectUnknownKeys(input, ["description", "projectRoot", "program", "args", "cwd", "timeoutSeconds"], label);
	const projectRoot = stringAt(input.projectRoot, `${label}.projectRoot`);
	const cwd = stringAt(input.cwd ?? projectRoot, `${label}.cwd`);
	if (!path.isAbsolute(projectRoot)) throw new GuardConfigError(`${label}.projectRoot must be absolute`);
	if (!path.isAbsolute(cwd)) throw new GuardConfigError(`${label}.cwd must be absolute`);
	return {
		description: stringAt(input.description, `${label}.description`),
		projectRoot,
		program: stringAt(input.program, `${label}.program`),
		args: stringArrayAt(input.args, `${label}.args`),
		cwd,
		timeoutSeconds: positiveIntegerAt(input.timeoutSeconds ?? 900, `${label}.timeoutSeconds`),
	};
}

function parseHostCommands(value: unknown, label: string): Record<string, HostCommandRule> {
	const input = objectAt(value, label);
	const output: Record<string, HostCommandRule> = {};
	for (const [id, rule] of Object.entries(input)) {
		if (!/^[a-z][a-z0-9-]*$/.test(id)) throw new GuardConfigError(`${label}.${id} must use lower-case kebab-case`);
		output[id] = parseHostCommand(rule, `${label}.${id}`);
	}
	return output;
}

function parseVersion(input: JsonObject, label: string): void {
	if (input.version !== CONFIG_VERSION) throw new GuardConfigError(`${label}.version must be ${CONFIG_VERSION}`);
}

export function parseGlobalConfig(value: unknown): GlobalGuardConfig {
	const input = objectAt(value, "global config");
	rejectUnknownKeys(
		input,
		["version", "mode", "filesystem", "network", "environment", "hostCommands", "externalTools", "userBash", "approvalTimeoutSeconds"],
		"global config",
	);
	parseVersion(input, "global config");

	const filesystemInput = input.filesystem === undefined ? {} : objectAt(input.filesystem, "filesystem");
	rejectUnknownKeys(filesystemInput, ["deny", "workspaceAccess"], "filesystem");
	const networkInput = input.network === undefined ? {} : objectAt(input.network, "network");
	rejectUnknownKeys(networkInput, ["allowedHosts", "blockInternalRanges"], "network");
	const environmentInput = input.environment === undefined ? {} : objectAt(input.environment, "environment");
	rejectUnknownKeys(environmentInput, ["allowFromHost", "values"], "environment");
	const externalToolsInput = input.externalTools === undefined ? {} : objectAt(input.externalTools, "externalTools");
	rejectUnknownKeys(externalToolsInput, ["allow"], "externalTools");

	const configuredDeny = filesystemInput.deny === undefined ? [] : parseDenyPatterns(filesystemInput.deny, "filesystem.deny");
	return {
		version: CONFIG_VERSION,
		mode: input.mode === undefined ? DEFAULT_GLOBAL_CONFIG.mode : enumAt(input.mode, ["strict", "compatible", "disabled"], "mode"),
		filesystem: {
			deny: deduplicate([...DEFAULT_DENIED_VFS_PATTERNS, ...configuredDeny]),
			workspaceAccess:
				filesystemInput.workspaceAccess === undefined
					? DEFAULT_GLOBAL_CONFIG.filesystem.workspaceAccess
					: enumAt(filesystemInput.workspaceAccess, ["read-write", "read-only"], "filesystem.workspaceAccess"),
		},
		network: {
			allowedHosts:
				networkInput.allowedHosts === undefined
					? [...DEFAULT_GLOBAL_CONFIG.network.allowedHosts]
					: parseAllowedHosts(networkInput.allowedHosts, "network.allowedHosts"),
			blockInternalRanges:
				networkInput.blockInternalRanges === undefined
					? DEFAULT_GLOBAL_CONFIG.network.blockInternalRanges
					: booleanAt(networkInput.blockInternalRanges, "network.blockInternalRanges"),
		},
		environment: {
			allowFromHost:
				environmentInput.allowFromHost === undefined
					? [...DEFAULT_GLOBAL_CONFIG.environment.allowFromHost]
					: stringArrayAt(environmentInput.allowFromHost, "environment.allowFromHost"),
			values:
				environmentInput.values === undefined
					? { ...DEFAULT_GLOBAL_CONFIG.environment.values }
					: parseStringRecord(environmentInput.values, "environment.values"),
		},
		hostCommands: input.hostCommands === undefined ? {} : parseHostCommands(input.hostCommands, "hostCommands"),
		externalTools: {
			allow: externalToolsInput.allow === undefined ? [] : stringArrayAt(externalToolsInput.allow, "externalTools.allow"),
		},
		userBash:
			input.userBash === undefined ? DEFAULT_GLOBAL_CONFIG.userBash : enumAt(input.userBash, ["sandbox", "host", "blocked"], "userBash"),
		approvalTimeoutSeconds:
			input.approvalTimeoutSeconds === undefined
				? DEFAULT_GLOBAL_CONFIG.approvalTimeoutSeconds
				: positiveIntegerAt(input.approvalTimeoutSeconds, "approvalTimeoutSeconds"),
	};
}

export function parseProjectConfig(value: unknown): ProjectGuardConfig {
	const input = objectAt(value, "project config");
	rejectUnknownKeys(input, ["version", "filesystem", "network"], "project config");
	parseVersion(input, "project config");
	const result: ProjectGuardConfig = { version: CONFIG_VERSION };
	if (input.filesystem !== undefined) {
		const filesystem = objectAt(input.filesystem, "filesystem");
		rejectUnknownKeys(filesystem, ["deny", "workspaceAccess"], "filesystem");
		result.filesystem = {};
		if (filesystem.deny !== undefined) result.filesystem.deny = parseDenyPatterns(filesystem.deny, "filesystem.deny");
		if (filesystem.workspaceAccess !== undefined) {
			result.filesystem.workspaceAccess = enumAt(filesystem.workspaceAccess, ["read-write", "read-only"], "filesystem.workspaceAccess");
		}
	}
	if (input.network !== undefined) {
		const network = objectAt(input.network, "network");
		rejectUnknownKeys(network, ["allowedHosts"], "network");
		result.network = {};
		if (network.allowedHosts !== undefined) result.network.allowedHosts = parseAllowedHosts(network.allowedHosts, "network.allowedHosts");
	}
	return result;
}

async function readJsonConfig(configPath: string): Promise<unknown | undefined> {
	let source: string;
	try {
		source = await readFile(configPath, "utf8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw new GuardConfigError("unable to read config", configPath, { cause: error });
	}
	try {
		return JSON.parse(source) as unknown;
	} catch (error) {
		throw new GuardConfigError("invalid JSON", configPath, { cause: error });
	}
}

function mergeProjectConfig(global: GlobalGuardConfig, project: ProjectGuardConfig | undefined): GlobalGuardConfig {
	if (!project) return global;
	const projectHosts = project.network?.allowedHosts;
	if (projectHosts) {
		const outsideCeiling = projectHosts.filter((host) => !global.network.allowedHosts.includes(host));
		if (outsideCeiling.length > 0) {
			throw new GuardConfigError(`project network hosts exceed the global ceiling: ${outsideCeiling.join(", ")}`);
		}
	}
	const workspaceAccess =
		global.filesystem.workspaceAccess === "read-only" || project.filesystem?.workspaceAccess === "read-only"
			? "read-only"
			: "read-write";
	return {
		...global,
		filesystem: {
			deny: deduplicate([...global.filesystem.deny, ...(project.filesystem?.deny ?? [])]),
			workspaceAccess,
		},
		network: {
			...global.network,
			allowedHosts: projectHosts ? [...projectHosts] : [...global.network.allowedHosts],
		},
	};
}

async function filterHostCommandsForProject(
	rules: Record<string, HostCommandRule>,
	canonicalProjectRoot: string,
): Promise<Record<string, HostCommandRule>> {
	const output: Record<string, HostCommandRule> = {};
	for (const [id, rule] of Object.entries(rules)) {
		let configuredRoot: string;
		let configuredCwd: string;
		try {
			configuredRoot = await realpath(rule.projectRoot);
			configuredCwd = await realpath(rule.cwd);
		} catch (error) {
			throw new GuardConfigError(`hostCommands.${id} references a path that cannot be canonicalized`, undefined, { cause: error });
		}
		if (configuredRoot !== canonicalProjectRoot) continue;
		output[id] = { ...rule, projectRoot: configuredRoot, cwd: configuredCwd };
	}
	return output;
}

export async function loadEffectiveConfig(options: LoadConfigOptions): Promise<EffectiveGuardConfig> {
	const canonicalProjectRoot = await realpath(options.projectRoot);
	const globalPath = path.join(options.agentDir, GLOBAL_CONFIG_FILENAME);
	const projectPath = path.join(canonicalProjectRoot, options.projectConfigDirName, PROJECT_CONFIG_FILENAME);

	const globalValue = await readJsonConfig(globalPath);
	let global: GlobalGuardConfig;
	try {
		global = globalValue === undefined ? structuredClone(DEFAULT_GLOBAL_CONFIG) : parseGlobalConfig(globalValue);
	} catch (error) {
		if (error instanceof GuardConfigError && !error.configPath) {
			throw new GuardConfigError(error.message, globalPath, { cause: error });
		}
		throw error;
	}

	let project: ProjectGuardConfig | undefined;
	if (options.projectTrusted) {
		const projectValue = await readJsonConfig(projectPath);
		if (projectValue !== undefined) {
			try {
				project = parseProjectConfig(projectValue);
			} catch (error) {
				if (error instanceof GuardConfigError && !error.configPath) {
					throw new GuardConfigError(error.message, projectPath, { cause: error });
				}
				throw error;
			}
		}
	}

	const merged = mergeProjectConfig(global, project);
	return {
		...merged,
		hostCommands: await filterHostCommandsForProject(merged.hostCommands, canonicalProjectRoot),
		canonicalProjectRoot,
		sources: {
			global: globalPath,
			...(project ? { project: projectPath } : {}),
		},
	};
}
