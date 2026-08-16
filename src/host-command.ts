import type { ExtensionAPI, ExtensionContext, TruncationResult } from "@earendil-works/pi-coding-agent";
import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, formatSize, truncateTail } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import type { EffectiveGuardConfig, HostCommandRule } from "./config.js";

const AUDIT_ENTRY_TYPE = "pi-guard-host-command";

const HostCommandParameters = Type.Object({
	rule: Type.String({ description: "Exact globally configured host-command rule identifier" }),
});

export type HostCommandOutcome =
	| "approved"
	| "denied"
	| "approval_timeout"
	| "cancelled"
	| "headless"
	| "completed"
	| "execution_timeout"
	| "failed";

export interface HostCommandAuditEntry {
	timestamp: string;
	ruleId: string;
	program: string;
	args: string[];
	cwd: string;
	timeoutSeconds: number;
	outcome: HostCommandOutcome;
	durationMs?: number;
	exitCode?: number;
	killed?: boolean;
}

export interface HostCommandDetails {
	ruleId: string;
	program: string;
	args: string[];
	cwd: string;
	timeoutSeconds: number;
	outcome: "completed" | "execution_timeout";
	exitCode: number;
	killed: boolean;
	durationMs: number;
	truncation?: TruncationResult;
}

export interface HostCommandExecResult {
	stdout: string;
	stderr: string;
	code: number;
	killed: boolean;
}

export interface HostCommandExecutionOptions {
	config: EffectiveGuardConfig;
	ruleId: string;
	hasUI: boolean;
	confirm: (title: string, message: string, options: { signal: AbortSignal }) => Promise<boolean>;
	exec: (
		program: string,
		args: string[],
		options: { cwd: string; signal: AbortSignal },
	) => Promise<HostCommandExecResult>;
	audit: (entry: HostCommandAuditEntry) => void;
	approvalQueue: SerializedApprovalQueue;
	signal?: AbortSignal;
}

export class HostCommandBlockedError extends Error {
	readonly outcome: HostCommandOutcome;

	constructor(message: string, outcome: HostCommandOutcome) {
		super(message);
		this.name = "HostCommandBlockedError";
		this.outcome = outcome;
	}
}

export class SerializedApprovalQueue {
	private tail: Promise<void> = Promise.resolve();

	async run<T>(operation: () => Promise<T>): Promise<T> {
		const previous = this.tail.catch(() => undefined);
		let release!: () => void;
		const current = new Promise<void>((resolve) => {
			release = resolve;
		});
		this.tail = previous.then(() => current);
		await previous;
		try {
			return await operation();
		} finally {
			release();
		}
	}
}

function auditBase(ruleId: string, rule: HostCommandRule): Omit<HostCommandAuditEntry, "timestamp" | "outcome"> {
	return {
		ruleId,
		program: rule.program,
		args: [...rule.args],
		cwd: rule.cwd,
		timeoutSeconds: rule.timeoutSeconds,
	};
}

function appendAudit(
	audit: (entry: HostCommandAuditEntry) => void,
	ruleId: string,
	rule: HostCommandRule,
	outcome: HostCommandOutcome,
	extra: Partial<Pick<HostCommandAuditEntry, "durationMs" | "exitCode" | "killed">> = {},
): void {
	audit({
		timestamp: new Date().toISOString(),
		...auditBase(ruleId, rule),
		outcome,
		...extra,
	});
}

export function formatHostCommandApproval(ruleId: string, rule: HostCommandRule): string {
	return [
		rule.description,
		"",
		`Rule: ${ruleId}`,
		`Program: ${JSON.stringify(rule.program)}`,
		`Argv: ${JSON.stringify(rule.args)}`,
		`Cwd: ${rule.cwd}`,
		`Execution timeout: ${rule.timeoutSeconds}s`,
		"",
		"This runs directly on the host without a shell.",
	].join("\n");
}

function linkedController(signal: AbortSignal | undefined): {
	controller: AbortController;
	removeListener: () => void;
} {
	const controller = new AbortController();
	const abort = () => controller.abort();
	if (signal?.aborted) controller.abort();
	else signal?.addEventListener("abort", abort, { once: true });
	return {
		controller,
		removeListener: () => signal?.removeEventListener("abort", abort),
	};
}

async function requireApproval(options: HostCommandExecutionOptions, rule: HostCommandRule): Promise<void> {
	if (!options.hasUI) {
		appendAudit(options.audit, options.ruleId, rule, "headless");
		throw new HostCommandBlockedError("Host command blocked: interactive approval is unavailable.", "headless");
	}
	if (options.signal?.aborted) {
		appendAudit(options.audit, options.ruleId, rule, "cancelled");
		throw new HostCommandBlockedError("Host command blocked: request was cancelled.", "cancelled");
	}

	await options.approvalQueue.run(async () => {
		if (options.signal?.aborted) {
			appendAudit(options.audit, options.ruleId, rule, "cancelled");
			throw new HostCommandBlockedError("Host command blocked: request was cancelled.", "cancelled");
		}
		const { controller, removeListener } = linkedController(options.signal);
		let timedOut = false;
		const timeout = setTimeout(() => {
			timedOut = true;
			controller.abort();
		}, options.config.approvalTimeoutSeconds * 1000);
		try {
			let approved: boolean;
			try {
				approved = await options.confirm(
					"Pi Guard: approve host command?",
					formatHostCommandApproval(options.ruleId, rule),
					{ signal: controller.signal },
				);
			} catch (cause) {
				const outcome = timedOut ? "approval_timeout" : options.signal?.aborted ? "cancelled" : "failed";
				appendAudit(options.audit, options.ruleId, rule, outcome);
				throw new HostCommandBlockedError(
					`Host command blocked: approval dialog failed${cause instanceof Error ? ` (${cause.message})` : ""}.`,
					outcome,
				);
			}
			if (!approved) {
				const outcome = timedOut ? "approval_timeout" : options.signal?.aborted ? "cancelled" : "denied";
				appendAudit(options.audit, options.ruleId, rule, outcome);
				const reason =
					outcome === "approval_timeout"
						? "approval timed out"
						: outcome === "cancelled"
							? "request was cancelled"
							: "approval was denied";
				throw new HostCommandBlockedError(`Host command blocked: ${reason}.`, outcome);
			}
			if (timedOut || options.signal?.aborted) {
				const outcome = timedOut ? "approval_timeout" : "cancelled";
				appendAudit(options.audit, options.ruleId, rule, outcome);
				throw new HostCommandBlockedError("Host command blocked: approval was no longer valid.", outcome);
			}
			appendAudit(options.audit, options.ruleId, rule, "approved");
		} finally {
			clearTimeout(timeout);
			removeListener();
		}
	});
}

function combineOutput(stdout: string, stderr: string): string {
	if (stdout && stderr) return `${stdout.replace(/\s+$/, "")}\n\n[stderr]\n${stderr}`;
	return stdout || stderr;
}

export async function executeHostCommand(options: HostCommandExecutionOptions): Promise<{
	content: Array<{ type: "text"; text: string }>;
	details: HostCommandDetails;
}> {
	if (options.config.mode === "disabled") {
		throw new HostCommandBlockedError("Host command tool is unavailable while Pi Guard is disabled.", "failed");
	}
	const rule = options.config.hostCommands[options.ruleId];
	if (!rule) {
		const available = Object.keys(options.config.hostCommands);
		throw new HostCommandBlockedError(
			available.length > 0
				? `Unknown host-command rule ${JSON.stringify(options.ruleId)}. Available rules: ${available.join(", ")}`
				: "No host-command rules are configured for this canonical project.",
			"failed",
		);
	}

	await requireApproval(options, rule);
	if (options.signal?.aborted) {
		appendAudit(options.audit, options.ruleId, rule, "cancelled");
		throw new HostCommandBlockedError("Host command blocked: request was cancelled after approval.", "cancelled");
	}

	const started = Date.now();
	const { controller, removeListener } = linkedController(options.signal);
	let timedOut = false;
	const timeout = setTimeout(() => {
		timedOut = true;
		controller.abort();
	}, rule.timeoutSeconds * 1000);
	let result: HostCommandExecResult;
	try {
		result = await options.exec(rule.program, [...rule.args], { cwd: rule.cwd, signal: controller.signal });
	} catch (cause) {
		const durationMs = Date.now() - started;
		const outcome = timedOut ? "execution_timeout" : options.signal?.aborted ? "cancelled" : "failed";
		appendAudit(options.audit, options.ruleId, rule, outcome, { durationMs });
		if (outcome === "execution_timeout") {
			throw new HostCommandBlockedError(`Host command exceeded its ${rule.timeoutSeconds}s execution timeout.`, outcome);
		}
		if (outcome === "cancelled") throw new HostCommandBlockedError("Host command was cancelled.", outcome);
		throw new Error(`Host command failed to start: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
	} finally {
		clearTimeout(timeout);
		removeListener();
	}

	const durationMs = Date.now() - started;
	const outcome = timedOut ? "execution_timeout" : options.signal?.aborted ? "cancelled" : "completed";
	appendAudit(options.audit, options.ruleId, rule, outcome, {
		durationMs,
		exitCode: result.code,
		killed: result.killed,
	});
	if (outcome === "cancelled") throw new HostCommandBlockedError("Host command was cancelled.", outcome);

	const rawOutput = combineOutput(result.stdout, result.stderr);
	const truncation = truncateTail(rawOutput, { maxLines: DEFAULT_MAX_LINES, maxBytes: DEFAULT_MAX_BYTES });
	const details: HostCommandDetails = {
		ruleId: options.ruleId,
		program: rule.program,
		args: [...rule.args],
		cwd: rule.cwd,
		timeoutSeconds: rule.timeoutSeconds,
		outcome,
		exitCode: result.code,
		killed: result.killed,
		durationMs,
		...(truncation.truncated ? { truncation } : {}),
	};
	let text = `Host command ${options.ruleId} ${outcome === "execution_timeout" ? "timed out" : `exited with code ${result.code}`}.`;
	if (truncation.content) text += `\n\n${truncation.content}`;
	if (truncation.truncated) {
		text += `\n\n[Output truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.]`;
	}
	return { content: [{ type: "text", text }], details };
}

export interface RegisterHostCommandOptions {
	resolveConfig: (ctx: ExtensionContext) => Promise<EffectiveGuardConfig>;
}

export function registerHostCommandTool(pi: ExtensionAPI, options: RegisterHostCommandOptions): void {
	const approvalQueue = new SerializedApprovalQueue();
	pi.registerTool({
		name: "host_command",
		label: "Host Command",
		description:
			"Run one exact user-owned global host-command rule. Every call requires interactive approval and never uses a shell.",
		promptSnippet: "Run an exact globally configured host operation after interactive user approval",
		promptGuidelines: [
			"Use host_command only with an available exact rule identifier; denial, cancellation, or timeout is final and must not be rerouted automatically.",
		],
		parameters: HostCommandParameters,
		async execute(_toolCallId, params, signal, _onUpdate, ctx) {
			const config = await options.resolveConfig(ctx);
			return executeHostCommand({
				config,
				ruleId: params.rule,
				hasUI: ctx.hasUI,
				confirm: (title, message, dialogOptions) => ctx.ui.confirm(title, message, dialogOptions),
				exec: (program, args, execOptions) => pi.exec(program, args, execOptions),
				audit: (entry) => pi.appendEntry(AUDIT_ENTRY_TYPE, entry),
				approvalQueue,
				...(signal ? { signal } : {}),
			});
		},
	});
}
