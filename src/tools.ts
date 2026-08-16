import path from "node:path";
import type { VM } from "@earendil-works/gondolin";
import {
	type BashOperations,
	createBashTool,
	createEditTool,
	createFindTool,
	createGrepTool,
	createLsTool,
	createReadTool,
	createWriteTool,
	DEFAULT_MAX_BYTES,
	type EditOperations,
	type ExtensionAPI,
	type ExtensionContext,
	type FindOperations,
	formatSize,
	type GrepToolDetails,
	type GrepToolInput,
	type LsOperations,
	type ReadOperations,
	truncateHead,
	truncateLine,
	type WriteOperations,
} from "@earendil-works/pi-coding-agent";
import type { EffectiveGuardConfig, EnvironmentPolicy } from "./config.js";
import { GUEST_WORKSPACE, type GuardVmManager } from "./gondolin.js";
import { buildGuestEnvironment } from "./policy.js";

const DEFAULT_GREP_LIMIT = 100;

export const ROUTED_CORE_TOOLS = new Set(["bash", "read", "write", "edit", "ls", "find", "grep"]);

type TextToolResult<TDetails> = {
	content: Array<{ type: "text"; text: string }>;
	details: TDetails | undefined;
};

export interface GuardRuntime {
	config: EffectiveGuardConfig;
	manager?: GuardVmManager;
}

export interface RegisterRoutedToolsOptions {
	localCwd: string;
	resolveRuntime: (ctx: ExtensionContext) => Promise<GuardRuntime>;
}

function stripAtPrefix(value: string): string {
	return value.startsWith("@") ? value.slice(1) : value;
}

function toPosix(value: string): string {
	return value.split(path.sep).join(path.posix.sep);
}

export function isInsideHostPath(root: string, value: string): boolean {
	const relativePath = path.relative(root, value);
	return relativePath === "" || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
}

export function hostPathToGuest(localCwd: string, hostPath: string): string {
	const relativePath = path.relative(localCwd, hostPath);
	if (!isInsideHostPath(localCwd, hostPath)) return toPosix(hostPath);
	return relativePath ? path.posix.join(GUEST_WORKSPACE, toPosix(relativePath)) : GUEST_WORKSPACE;
}

export function toGuestPath(localCwd: string, inputPath: string): string {
	const trimmed = stripAtPrefix(inputPath.trim());
	if (!trimmed) return GUEST_WORKSPACE;
	if (path.isAbsolute(trimmed)) {
		if (isInsideHostPath(localCwd, trimmed)) return hostPathToGuest(localCwd, trimmed);
		return path.posix.resolve("/", toPosix(trimmed));
	}
	return path.posix.resolve(GUEST_WORKSPACE, toPosix(trimmed));
}

export function createGondolinReadOps(vm: VM, localCwd: string): ReadOperations {
	return {
		readFile: async (filePath) => vm.fs.readFile(toGuestPath(localCwd, filePath)),
		access: async (filePath) => {
			await vm.fs.access(toGuestPath(localCwd, filePath));
		},
		detectImageMimeType: async (filePath) => {
			const ext = path.posix.extname(toGuestPath(localCwd, filePath)).toLowerCase();
			if (ext === ".png") return "image/png";
			if (ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
			if (ext === ".gif") return "image/gif";
			if (ext === ".webp") return "image/webp";
			return null;
		},
	};
}

export function createGondolinWriteOps(vm: VM, localCwd: string): WriteOperations {
	return {
		writeFile: async (filePath, content) => {
			await vm.fs.writeFile(toGuestPath(localCwd, filePath), content, { encoding: "utf8" });
		},
		mkdir: async (dirPath) => {
			await vm.fs.mkdir(toGuestPath(localCwd, dirPath), { recursive: true });
		},
	};
}

export function createGondolinEditOps(vm: VM, localCwd: string): EditOperations {
	const readOps = createGondolinReadOps(vm, localCwd);
	const writeOps = createGondolinWriteOps(vm, localCwd);
	return {
		readFile: readOps.readFile,
		writeFile: writeOps.writeFile,
		access: readOps.access,
	};
}

export function createGondolinLsOps(vm: VM, localCwd: string): LsOperations {
	return {
		exists: async (filePath) => {
			try {
				await vm.fs.access(toGuestPath(localCwd, filePath));
				return true;
			} catch {
				return false;
			}
		},
		stat: async (filePath) => vm.fs.stat(toGuestPath(localCwd, filePath)),
		readdir: async (dirPath) => vm.fs.listDir(toGuestPath(localCwd, dirPath)),
	};
}

async function walkGuestFiles(
	vm: VM,
	root: string,
	visit: (guestPath: string, relativePath: string) => Promise<boolean>,
	signal?: AbortSignal,
): Promise<boolean> {
	if (signal?.aborted) throw new Error("Operation aborted");
	const stat = await vm.fs.stat(root, signal ? { signal } : {});
	if (!stat.isDirectory()) return visit(root, path.posix.basename(root));

	const walkDirectory = async (dir: string, relativeDir: string): Promise<boolean> => {
		if (signal?.aborted) throw new Error("Operation aborted");
		const entries = await vm.fs.listDir(dir, signal ? { signal } : {});
		for (const entry of entries) {
			if (entry === ".git" || entry === "node_modules") continue;
			const guestPath = path.posix.join(dir, entry);
			const relativePath = relativeDir ? path.posix.join(relativeDir, entry) : entry;
			let entryStat: Awaited<ReturnType<VM["fs"]["stat"]>>;
			try {
				entryStat = await vm.fs.stat(guestPath, signal ? { signal } : {});
			} catch {
				continue;
			}
			if (entryStat.isDirectory()) {
				if (!(await walkDirectory(guestPath, relativePath))) return false;
			} else if (!(await visit(guestPath, relativePath))) {
				return false;
			}
		}
		return true;
	};

	return walkDirectory(root, "");
}

function matchesToolGlob(relativePath: string, pattern: string): boolean {
	const normalizedPattern = toPosix(pattern);
	if (normalizedPattern.includes("/")) {
		return (
			path.posix.matchesGlob(relativePath, normalizedPattern) ||
			path.posix.matchesGlob(relativePath, `**/${normalizedPattern}`)
		);
	}
	return path.posix.matchesGlob(path.posix.basename(relativePath), normalizedPattern);
}

export function createGondolinFindOps(vm: VM, localCwd: string): FindOperations {
	return {
		exists: async (filePath) => {
			try {
				await vm.fs.access(toGuestPath(localCwd, filePath));
				return true;
			} catch {
				return false;
			}
		},
		glob: async (pattern, cwd, options) => {
			const root = toGuestPath(localCwd, cwd);
			const results: string[] = [];
			await walkGuestFiles(vm, root, async (guestPath, relativePath) => {
				if (results.length >= options.limit) return false;
				if (matchesToolGlob(relativePath, pattern)) results.push(guestPath);
				return results.length < options.limit;
			});
			return results;
		},
	};
}

function createLineMatcher(pattern: string, literal: boolean | undefined, ignoreCase: boolean | undefined) {
	if (literal) {
		const needle = ignoreCase ? pattern.toLowerCase() : pattern;
		return (line: string) => (ignoreCase ? line.toLowerCase() : line).includes(needle);
	}
	const regex = new RegExp(pattern, ignoreCase ? "i" : undefined);
	return (line: string) => regex.test(line);
}

function appendGrepBlock(params: {
	outputLines: string[];
	lines: string[];
	relativePath: string;
	lineIndex: number;
	contextLines: number;
}): boolean {
	let linesTruncated = false;
	const start = params.contextLines > 0 ? Math.max(0, params.lineIndex - params.contextLines) : params.lineIndex;
	const end =
		params.contextLines > 0
			? Math.min(params.lines.length - 1, params.lineIndex + params.contextLines)
			: params.lineIndex;
	for (let index = start; index <= end; index++) {
		const rawLine = params.lines[index] ?? "";
		const { text, wasTruncated } = truncateLine(rawLine.replace(/\r/g, ""));
		if (wasTruncated) linesTruncated = true;
		const separator = index === params.lineIndex ? ":" : "-";
		params.outputLines.push(`${params.relativePath}${separator}${index + 1}${separator} ${text}`);
	}
	return linesTruncated;
}

export async function executeGondolinGrep(
	vm: VM,
	localCwd: string,
	params: GrepToolInput,
	signal?: AbortSignal,
): Promise<TextToolResult<GrepToolDetails>> {
	const root = toGuestPath(localCwd, params.path ?? ".");
	const rootStat = await vm.fs.stat(root, signal ? { signal } : {});
	const rootIsDirectory = rootStat.isDirectory();
	const matcher = createLineMatcher(params.pattern, params.literal, params.ignoreCase);
	const contextLines = params.context && params.context > 0 ? params.context : 0;
	const effectiveLimit = Math.max(1, params.limit ?? DEFAULT_GREP_LIMIT);
	const outputLines: string[] = [];
	const details: GrepToolDetails = {};
	let matchCount = 0;
	let matchLimitReached = false;
	let linesTruncated = false;

	await walkGuestFiles(
		vm,
		root,
		async (guestPath, relativePath) => {
			if (matchCount >= effectiveLimit) return false;
			if (params.glob && !matchesToolGlob(relativePath, params.glob)) return true;
			let content: string;
			try {
				content = await vm.fs.readFile(guestPath, { encoding: "utf8", ...(signal ? { signal } : {}) });
			} catch {
				return true;
			}
			const lines = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
			const displayPath = rootIsDirectory ? relativePath : path.posix.basename(guestPath);
			for (let index = 0; index < lines.length; index++) {
				if (signal?.aborted) throw new Error("Operation aborted");
				if (!matcher(lines[index] ?? "")) continue;
				matchCount++;
				if (appendGrepBlock({ outputLines, lines, relativePath: displayPath, lineIndex: index, contextLines })) {
					linesTruncated = true;
				}
				if (matchCount >= effectiveLimit) {
					matchLimitReached = true;
					return false;
				}
			}
			return true;
		},
		signal,
	);

	if (matchCount === 0) return { content: [{ type: "text", text: "No matches found" }], details: undefined };
	const rawOutput = outputLines.join("\n");
	const truncation = truncateHead(rawOutput, { maxLines: Number.MAX_SAFE_INTEGER });
	const notices: string[] = [];
	let output = truncation.content;
	if (matchLimitReached) {
		details.matchLimitReached = effectiveLimit;
		notices.push(`${effectiveLimit} matches limit reached`);
	}
	if (linesTruncated) {
		details.linesTruncated = true;
		notices.push("long lines truncated");
	}
	if (truncation.truncated) {
		details.truncation = truncation;
		notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
	}
	if (notices.length > 0) output += `\n\n[${notices.join(". ")}]`;
	return {
		content: [{ type: "text", text: output }],
		details: Object.keys(details).length > 0 ? details : undefined,
	};
}

export function createGondolinBashOps(
	vm: VM,
	localCwd: string,
	shellPath: string,
	environmentPolicy: EnvironmentPolicy,
): BashOperations {
	return {
		exec: async (command, cwd, { onData, signal, timeout, env }) => {
			if (signal?.aborted) throw new Error("aborted");
			const guestCwd = toGuestPath(localCwd, cwd);
			const controller = new AbortController();
			const onAbort = () => controller.abort();
			signal?.addEventListener("abort", onAbort, { once: true });
			let timedOut = false;
			const timer =
				timeout && timeout > 0
					? setTimeout(() => {
							timedOut = true;
							controller.abort();
						}, timeout * 1000)
					: undefined;
			try {
				const proc = vm.exec([shellPath, "-lc", command], {
					cwd: guestCwd,
					env: buildGuestEnvironment(environmentPolicy, env ?? {}),
					signal: controller.signal,
					stdout: "pipe",
					stderr: "pipe",
				});
				for await (const chunk of proc.output()) onData(chunk.data);
				const result = await proc;
				return { exitCode: result.exitCode };
			} catch (error) {
				if (signal?.aborted) throw new Error("aborted");
				if (timedOut) throw new Error(`timeout:${timeout}`);
				throw error;
			} finally {
				if (timer) clearTimeout(timer);
				signal?.removeEventListener("abort", onAbort);
			}
		},
	};
}

async function requireVm(runtime: GuardRuntime): Promise<{ vm: VM; manager: GuardVmManager }> {
	if (!runtime.manager) throw new Error("Pi Guard VM is unavailable; operation blocked.");
	return { vm: await runtime.manager.ensureStarted(), manager: runtime.manager };
}

export function registerRoutedTools(pi: ExtensionAPI, options: RegisterRoutedToolsOptions): void {
	const localRead = createReadTool(options.localCwd);
	const localWrite = createWriteTool(options.localCwd);
	const localEdit = createEditTool(options.localCwd);
	const localBash = createBashTool(options.localCwd);
	const localGrep = createGrepTool(options.localCwd);
	const localFind = createFindTool(options.localCwd);
	const localLs = createLsTool(options.localCwd);

	pi.registerTool({
		...localRead,
		async execute(id, params, signal, onUpdate, ctx) {
			const runtime = await options.resolveRuntime(ctx);
			if (runtime.config.mode !== "strict") return localRead.execute(id, params, signal, onUpdate);
			const { vm } = await requireVm(runtime);
			return createReadTool(GUEST_WORKSPACE, { operations: createGondolinReadOps(vm, runtime.config.canonicalProjectRoot) }).execute(
				id,
				params,
				signal,
				onUpdate,
			);
		},
	});

	pi.registerTool({
		...localWrite,
		async execute(id, params, signal, onUpdate, ctx) {
			const runtime = await options.resolveRuntime(ctx);
			if (runtime.config.mode !== "strict") return localWrite.execute(id, params, signal, onUpdate);
			const { vm } = await requireVm(runtime);
			return createWriteTool(GUEST_WORKSPACE, { operations: createGondolinWriteOps(vm, runtime.config.canonicalProjectRoot) }).execute(
				id,
				params,
				signal,
				onUpdate,
			);
		},
	});

	pi.registerTool({
		...localEdit,
		async execute(id, params, signal, onUpdate, ctx) {
			const runtime = await options.resolveRuntime(ctx);
			if (runtime.config.mode !== "strict") return localEdit.execute(id, params, signal, onUpdate);
			const { vm } = await requireVm(runtime);
			return createEditTool(GUEST_WORKSPACE, { operations: createGondolinEditOps(vm, runtime.config.canonicalProjectRoot) }).execute(
				id,
				params,
				signal,
				onUpdate,
			);
		},
	});

	pi.registerTool({
		...localBash,
		async execute(id, params, signal, onUpdate, ctx) {
			const runtime = await options.resolveRuntime(ctx);
			if (runtime.config.mode === "disabled") return localBash.execute(id, params, signal, onUpdate);
			const { vm, manager } = await requireVm(runtime);
			return createBashTool(GUEST_WORKSPACE, {
				operations: createGondolinBashOps(
					vm,
					runtime.config.canonicalProjectRoot,
					manager.shellPath,
					runtime.config.environment,
				),
				exposeSessionEnvironment: false,
			}).execute(id, params, signal, onUpdate);
		},
	});

	pi.registerTool({
		...localLs,
		async execute(id, params, signal, onUpdate, ctx) {
			const runtime = await options.resolveRuntime(ctx);
			if (runtime.config.mode !== "strict") return localLs.execute(id, params, signal, onUpdate);
			const { vm } = await requireVm(runtime);
			return createLsTool(GUEST_WORKSPACE, { operations: createGondolinLsOps(vm, runtime.config.canonicalProjectRoot) }).execute(
				id,
				params,
				signal,
				onUpdate,
			);
		},
	});

	pi.registerTool({
		...localFind,
		async execute(id, params, signal, onUpdate, ctx) {
			const runtime = await options.resolveRuntime(ctx);
			if (runtime.config.mode !== "strict") return localFind.execute(id, params, signal, onUpdate);
			const { vm } = await requireVm(runtime);
			return createFindTool(GUEST_WORKSPACE, { operations: createGondolinFindOps(vm, runtime.config.canonicalProjectRoot) }).execute(
				id,
				params,
				signal,
				onUpdate,
			);
		},
	});

	pi.registerTool({
		...localGrep,
		async execute(_id, params, signal, _onUpdate, ctx) {
			const runtime = await options.resolveRuntime(ctx);
			if (runtime.config.mode !== "strict") return localGrep.execute(_id, params, signal, _onUpdate);
			const { vm } = await requireVm(runtime);
			return executeGondolinGrep(vm, runtime.config.canonicalProjectRoot, params, signal);
		},
	});

	pi.on("user_bash", async (_event, ctx) => {
		const runtime = await options.resolveRuntime(ctx);
		if (runtime.config.mode === "disabled" || runtime.config.userBash === "host") return undefined;
		if (runtime.config.userBash === "blocked") {
			return {
				result: {
					output: "Pi Guard policy blocks user Bash commands.",
					exitCode: 126,
					cancelled: false,
					truncated: false,
				},
			};
		}
		const { vm, manager } = await requireVm(runtime);
		return {
			operations: createGondolinBashOps(
				vm,
				runtime.config.canonicalProjectRoot,
				manager.shellPath,
				runtime.config.environment,
			),
		};
	});

	pi.on("before_agent_start", async (event, ctx) => {
		const runtime = await options.resolveRuntime(ctx);
		if (runtime.config.mode === "disabled") return undefined;
		await requireVm(runtime);
		const localLine = `Current working directory: ${runtime.config.canonicalProjectRoot}`;
		const scope =
			runtime.config.mode === "strict"
				? `Current working directory: ${GUEST_WORKSPACE} (Pi Guard VM; host workspace mounted from ${runtime.config.canonicalProjectRoot})`
				: `Model Bash runs in ${GUEST_WORKSPACE} (Pi Guard compatible mode; filesystem tools may run on the host at ${runtime.config.canonicalProjectRoot})`;
		const systemPrompt = event.systemPrompt.includes(localLine)
			? event.systemPrompt.replace(localLine, scope)
			: `${event.systemPrompt}\n\n${scope}`;
		return { systemPrompt };
	});
}
