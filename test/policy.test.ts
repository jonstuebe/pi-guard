import assert from "node:assert/strict";
import test from "node:test";
import { buildGuestEnvironment, createDeniedPathPredicate } from "../src/policy.js";

test("denied path policy hides exact paths, descendants, and glob matches", () => {
	const denied = createDeniedPathPredicate(["/.env", "/.env.*", "/secrets/**", "/*.key"]);
	assert.equal(denied({ path: "/.env" }), true);
	assert.equal(denied({ path: "/.env.local" }), true);
	assert.equal(denied({ path: "/secrets" }), true);
	assert.equal(denied({ path: "/secrets/nested/token" }), true);
	assert.equal(denied({ path: "/private.key" }), true);
	assert.equal(denied({ path: "/src/index.ts" }), false);
});

test("guest environment copies only allowlisted names and applies fixed values", () => {
	const guest = buildGuestEnvironment(
		{
			allowFromHost: ["LANG", "LC_*"],
			values: { HOME: "/root", PATH: "/usr/bin" },
		},
		{
			LANG: "en_US.UTF-8",
			LC_ALL: "C",
			API_KEY: "secret",
			SSH_AUTH_SOCK: "/tmp/agent.sock",
			PATH: "/host/private/bin",
		},
	);
	assert.deepEqual(guest, {
		LANG: "en_US.UTF-8",
		LC_ALL: "C",
		HOME: "/root",
		PATH: "/usr/bin",
	});
});
