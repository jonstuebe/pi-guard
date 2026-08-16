import path from "node:path";
import {
	createHttpHooks,
	RealFSProvider,
	ReadonlyProvider,
	ShadowProvider,
	VM,
} from "@earendil-works/gondolin";
import type { EffectiveGuardConfig } from "./config.js";
import { buildGuestEnvironment, createDeniedPathPredicate } from "./policy.js";

export const GUEST_WORKSPACE = "/workspace";

export type GuardVmState = "idle" | "starting" | "ready" | "blocked" | "stopping" | "stopped";

export interface GuardVmSnapshot {
	state: GuardVmState;
	vmId?: string;
	shellPath?: string;
	error?: Error;
}

export type GuardVmFactory = (options: Parameters<typeof VM.create>[0]) => Promise<VM>;

export interface GuardVmManagerOptions {
	config: EffectiveGuardConfig;
	onStateChange?: (snapshot: GuardVmSnapshot) => void;
	/** Test and embedding seam. Production callers use VM.create directly. */
	createVm?: GuardVmFactory;
}

export class GuardVmManager {
	readonly #config: EffectiveGuardConfig;
	readonly #onStateChange: ((snapshot: GuardVmSnapshot) => void) | undefined;
	readonly #createVm: GuardVmFactory;
	#vm: VM | undefined;
	#starting: Promise<VM> | undefined;
	#closing: Promise<void> | undefined;
	#shellPath = "/bin/sh";
	#snapshot: GuardVmSnapshot = { state: "idle" };

	constructor(options: GuardVmManagerOptions) {
		this.#config = options.config;
		this.#onStateChange = options.onStateChange;
		this.#createVm = options.createVm ?? ((vmOptions) => VM.create(vmOptions));
	}

	get snapshot(): GuardVmSnapshot {
		return { ...this.#snapshot };
	}

	get shellPath(): string {
		return this.#shellPath;
	}

	async ensureStarted(): Promise<VM> {
		if (this.#vm) return this.#vm;
		if (this.#closing) await this.#closing;
		if (!this.#starting) {
			this.#starting = this.#start().finally(() => {
				this.#starting = undefined;
			});
		}
		return this.#starting;
	}

	async close(): Promise<void> {
		if (this.#closing) return this.#closing;
		this.#closing = this.#close().finally(() => {
			this.#closing = undefined;
		});
		return this.#closing;
	}

	async #start(): Promise<VM> {
		this.#setState({ state: "starting" });
		const workspaceBase = new RealFSProvider(this.#config.canonicalProjectRoot);
		const hiddenWorkspace = new ShadowProvider(workspaceBase, {
			shouldShadow: createDeniedPathPredicate(this.#config.filesystem.deny),
			writeMode: "deny",
			denySymlinkBypass: true,
		});
		const workspace =
			this.#config.filesystem.workspaceAccess === "read-only"
				? new ReadonlyProvider(hiddenWorkspace)
				: hiddenWorkspace;
		const { httpHooks } = createHttpHooks({
			allowedHosts: this.#config.network.allowedHosts,
			blockInternalRanges: this.#config.network.blockInternalRanges,
		});

		let created: VM | undefined;
		try {
			created = await this.#createVm({
				sessionLabel: `pi-guard ${path.basename(this.#config.canonicalProjectRoot)}`,
				env: buildGuestEnvironment(this.#config.environment),
				httpHooks,
				allowWebSockets: false,
				dns: { mode: "synthetic" },
				vfs: {
					mounts: {
						[GUEST_WORKSPACE]: workspace,
					},
				},
			});
			const probe = await created.exec(["/bin/sh", "-lc", "command -v bash || true"]);
			this.#shellPath = probe.stdout.trim() || "/bin/sh";
			this.#vm = created;
			this.#setState({ state: "ready", vmId: created.id, shellPath: this.#shellPath });
			return created;
		} catch (cause) {
			if (created) await created.close().catch(() => undefined);
			const error = cause instanceof Error ? cause : new Error(String(cause));
			this.#setState({ state: "blocked", error });
			throw error;
		}
	}

	async #close(): Promise<void> {
		const starting = this.#starting;
		if (starting) await starting.catch(() => undefined);
		const active = this.#vm;
		this.#vm = undefined;
		if (!active) {
			this.#setState({ state: "stopped" });
			return;
		}
		this.#setState({ state: "stopping", vmId: active.id, shellPath: this.#shellPath });
		try {
			await active.close();
		} finally {
			this.#setState({ state: "stopped" });
		}
	}

	#setState(snapshot: GuardVmSnapshot): void {
		this.#snapshot = snapshot;
		this.#onStateChange?.({ ...snapshot });
	}
}
