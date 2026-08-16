import {
	CONFIG_DIR_NAME,
	getAgentDir,
	type ExtensionAPI,
	type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { loadEffectiveConfig, type EffectiveGuardConfig } from "./config.js";
import { formatDiagnostics, runDiagnostics } from "./diagnostics.js";
import { GUEST_WORKSPACE, GuardVmManager, type GuardVmSnapshot } from "./gondolin.js";
import { formatHostCommandApproval, registerHostCommandTool } from "./host-command.js";
import { createDeniedPathPredicate } from "./policy.js";
import { registerRoutedTools, ROUTED_CORE_TOOLS, toGuestPath, type GuardRuntime } from "./tools.js";

const STATUS_KEY = "pi-guard";
const GUARD_OWNED_TOOLS = new Set([...ROUTED_CORE_TOOLS, "host_command"]);

export default function piGuard(pi: ExtensionAPI): void {
	let config: EffectiveGuardConfig | undefined;
	let manager: GuardVmManager | undefined;
	let initializationError: Error | undefined;
	let initializing: Promise<void> | undefined;
	let latestContext: ExtensionContext | undefined;

	function setStatus(ctx: ExtensionContext, snapshot: GuardVmSnapshot): void {
		if (!ctx.hasUI) return;
		const network = config?.network.allowedHosts.length === 0 ? "network deny-all" : "network filtered";
		const mode = config?.mode ?? "blocked";
		const text =
			snapshot.state === "ready"
				? `Pi Guard: ${mode} · VM ready · ${network}`
				: `Pi Guard: ${snapshot.state}`;
		const color =
			snapshot.state === "blocked" || mode !== "strict"
				? "warning"
				: snapshot.state === "ready"
					? "accent"
					: "muted";
		ctx.ui.setStatus(STATUS_KEY, ctx.ui.theme.fg(color, text));
	}

	async function initializeOnce(ctx: ExtensionContext): Promise<void> {
		latestContext = ctx;
		try {
			config = await loadEffectiveConfig({
				agentDir: getAgentDir(),
				projectRoot: ctx.cwd,
				projectConfigDirName: CONFIG_DIR_NAME,
				projectTrusted: ctx.isProjectTrusted(),
			});
			initializationError = undefined;
			if (config.mode === "disabled") {
				if (ctx.hasUI) ctx.ui.setStatus(STATUS_KEY, ctx.ui.theme.fg("warning", "Pi Guard: disabled (host tools active)"));
				return;
			}
			manager = new GuardVmManager({
				config,
				onStateChange: (snapshot) => setStatus(latestContext ?? ctx, snapshot),
			});
			await manager.ensureStarted();
			if (ctx.hasUI && config.mode === "compatible") {
				ctx.ui.notify("Pi Guard compatible mode is active; this is not a complete security boundary.", "warning");
			}
		} catch (cause) {
			initializationError = cause instanceof Error ? cause : new Error(String(cause));
			if (ctx.hasUI) {
				ctx.ui.setStatus(STATUS_KEY, ctx.ui.theme.fg("error", "Pi Guard: blocked"));
				ctx.ui.notify(`Pi Guard failed closed: ${initializationError.message}`, "error");
			}
		}
	}

	async function ensureInitialized(ctx: ExtensionContext): Promise<void> {
		latestContext = ctx;
		if (config && !initializationError) return;
		if (!initializing) {
			initializing = initializeOnce(ctx).finally(() => {
				initializing = undefined;
			});
		}
		await initializing;
	}

	async function resolveRuntime(ctx: ExtensionContext): Promise<GuardRuntime> {
		await ensureInitialized(ctx);
		if (initializationError) throw new Error(`Pi Guard initialization failed: ${initializationError.message}`);
		if (!config) throw new Error("Pi Guard configuration is unavailable; operation blocked.");
		return { config, ...(manager ? { manager } : {}) };
	}

	registerRoutedTools(pi, {
		localCwd: process.cwd(),
		resolveRuntime,
	});
	registerHostCommandTool(pi, {
		resolveConfig: async (ctx) => (await resolveRuntime(ctx)).config,
	});

	pi.on("session_start", async (_event, ctx) => {
		await ensureInitialized(ctx);
		if (!config || config.mode !== "strict") return;
		const active = pi.getActiveTools();
		const tools = new Map(pi.getAllTools().map((tool) => [tool.name, tool]));
		const blocked = active.filter((name) => {
			if (GUARD_OWNED_TOOLS.has(name) || config?.externalTools.allow.includes(name)) return false;
			const source = tools.get(name)?.sourceInfo.source;
			return source !== "builtin" && source !== "sdk";
		});
		const explicitlyTrusted = active.filter(
			(name) => !GUARD_OWNED_TOOLS.has(name) && config?.externalTools.allow.includes(name),
		);
		const nextActive = active.filter(
			(name) => !blocked.includes(name) && (name !== "host_command" || Object.keys(config?.hostCommands ?? {}).length > 0),
		);
		if (nextActive.length !== active.length) pi.setActiveTools(nextActive);
		if (ctx.hasUI && (blocked.length > 0 || explicitlyTrusted.length > 0)) {
			ctx.ui.notify(
				[
					...(blocked.length > 0 ? [`Disabled unapproved external tools: ${blocked.join(", ")}`] : []),
					...(explicitlyTrusted.length > 0
						? [`Explicitly trusted host-capable tools: ${explicitlyTrusted.join(", ")}`]
						: []),
				].join("\n"),
				"warning",
			);
		}
	});

	pi.on("before_agent_start", async (event, ctx) => {
		const runtime = await resolveRuntime(ctx);
		const rules = Object.entries(runtime.config.hostCommands);
		if (rules.length === 0 || runtime.config.mode === "disabled") return undefined;
		const ruleText = rules.map(([id, rule]) => `- ${id}: ${rule.description}`).join("\n");
		return {
			systemPrompt: `${event.systemPrompt}\n\nPi Guard host-command rules available for this canonical project:\n${ruleText}`,
		};
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		latestContext = ctx;
		await manager?.close();
		manager = undefined;
		if (ctx.hasUI) ctx.ui.setStatus(STATUS_KEY, undefined);
	});

	pi.on("tool_call", async (event) => {
		if (config?.mode === "disabled") return undefined;
		if (initializationError) {
			return { block: true, reason: `Pi Guard initialization failed: ${initializationError.message}` };
		}
		if (!config) return { block: true, reason: "Pi Guard has not initialized; tool call blocked." };
		if (config.mode === "strict" && !GUARD_OWNED_TOOLS.has(event.toolName)) {
			const tool = pi.getAllTools().find((candidate) => candidate.name === event.toolName);
			const isBuiltinOrSdk = tool?.sourceInfo.source === "builtin" || tool?.sourceInfo.source === "sdk";
			if (!isBuiltinOrSdk && !config.externalTools.allow.includes(event.toolName)) {
				return { block: true, reason: `Pi Guard blocked unapproved external tool: ${event.toolName}` };
			}
		}
		return undefined;
	});

	pi.registerCommand("guard", {
		description: "Show Pi Guard status and effective policy",
		handler: async (_args, ctx) => {
			latestContext = ctx;
			await ensureInitialized(ctx);
			if (initializationError) {
				ctx.ui.notify(`Pi Guard is blocked: ${initializationError.message}`, "error");
				return;
			}
			if (!config) return;
			ctx.ui.notify(
				[
					`Mode: ${config.mode}`,
					`Workspace: ${config.canonicalProjectRoot} → /workspace (${config.filesystem.workspaceAccess})`,
					`Denied path rules: ${config.filesystem.deny.length}`,
					`Network: ${config.network.allowedHosts.length === 0 ? "deny-all" : config.network.allowedHosts.join(", ")}`,
					`VM: ${manager?.snapshot.state ?? "not started"}`,
					`Host-command rules: ${Object.keys(config.hostCommands).length}`,
					"Implementation: Phase 3 host operations and UX",
				].join("\n"),
				config.mode === "strict" ? "info" : "warning",
			);
		},
	});

	pi.registerCommand("guard-explain", {
		description: "Explain Pi Guard's boundary or one configured host-command rule",
		handler: async (args, ctx) => {
			latestContext = ctx;
			await ensureInitialized(ctx);
			if (initializationError || !config) {
				ctx.ui.notify(`Pi Guard is blocked: ${initializationError?.message ?? "configuration unavailable"}`, "error");
				return;
			}
			const subject = args.trim();
			if (subject) {
				const rule = config.hostCommands[subject];
				if (rule) {
					ctx.ui.notify(formatHostCommandApproval(subject, rule), "info");
					return;
				}
				const guestPath = toGuestPath(config.canonicalProjectRoot, subject);
				const insideWorkspace = guestPath === GUEST_WORKSPACE || guestPath.startsWith(`${GUEST_WORKSPACE}/`);
				if (!insideWorkspace) {
					ctx.ui.notify(
						[`Path: ${subject}`, `Guest resolution: ${guestPath}`, "Decision: denied — outside the mounted /workspace tree."].join("\n"),
						"warning",
					);
					return;
				}
				const providerPath = guestPath === GUEST_WORKSPACE ? "/" : guestPath.slice(GUEST_WORKSPACE.length);
				const denied = createDeniedPathPredicate(config.filesystem.deny)({ path: providerPath });
				ctx.ui.notify(
					[
						`Path: ${subject}`,
						`Guest resolution: ${guestPath}`,
						denied
							? "Decision: denied — matched the effective hidden-path policy."
							: `Decision: lexically allowed (${config.filesystem.workspaceAccess}); VFS symlink checks still apply.`,
					].join("\n"),
					denied ? "warning" : "info",
				);
				return;
			}
			const rules = Object.entries(config.hostCommands).map(([id, rule]) => `  ${id}: ${rule.description}`);
			ctx.ui.notify(
				[
					`Mode: ${config.mode}`,
					"Strict mode routes built-in Bash and filesystem tools through Gondolin.",
					"Only the canonical project root is mounted; denied paths are hidden by the VFS.",
					"Guest network and environment access follow the effective global policy.",
					"Host commands use exact global rules, require approval every time, and never invoke a shell.",
					"Configured host-command rules:",
					...(rules.length > 0 ? rules : ["  (none)"]),
				].join("\n"),
				config.mode === "strict" ? "info" : "warning",
			);
		},
	});

	pi.registerCommand("guard-doctor", {
		description: "Run Pi Guard configuration and runtime diagnostics",
		handler: async (_args, ctx) => {
			latestContext = ctx;
			await ensureInitialized(ctx);
			if (initializationError || !config) {
				ctx.ui.notify(`✗ Initialization: ${initializationError?.message ?? "configuration unavailable"}`, "error");
				return;
			}
			const checks = await runDiagnostics(config, manager?.snapshot ?? { state: "idle" });
			ctx.ui.notify(formatDiagnostics(checks), checks.every((check) => check.ok) ? "info" : "warning");
		},
	});
}
