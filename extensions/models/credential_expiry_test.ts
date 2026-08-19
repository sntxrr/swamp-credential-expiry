// extensions/models/credential_expiry_test.ts
import { assertEquals } from "jsr:@std/assert@1";
import {
  classify,
  decodeJwtExp,
  parseGithubExpiryHeader,
  parseGitlabExpiryDate,
  PROBE_KINDS,
  probeFor,
} from "./credential_expiry.ts";

/** Build an unsigned-but-well-formed JWT with the given payload. */
function jwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(
      /=+$/,
      "",
    );
  return `${b64({ alg: "ES256", typ: "JWT" })}.${b64(payload)}.c2ln`;
}

Deno.test("decodeJwtExp reads the exp claim", () => {
  assertEquals(decodeJwtExp(jwt({ exp: 1794609198, jti: "abc" })), 1794609198);
});

Deno.test("decodeJwtExp distinguishes 'no exp' from 'malformed'", () => {
  // A token with no exp claim at all is the case that started this whole
  // programme: not invalid, just invisible to every clock.
  assertEquals(decodeJwtExp(jwt({ jti: "abc" })), null);
  assertEquals(decodeJwtExp("not-a-jwt"), "malformed");
  assertEquals(decodeJwtExp(""), "malformed");
});

Deno.test("decodeJwtExp rejects a truncated token rather than guessing", () => {
  // Transcripts held a truncated copy of a leaked token alongside an intact
  // one. A truncated value must not be silently treated as expiry-less.
  const full = jwt({ exp: 1794609198 });
  assertEquals(decodeJwtExp(full.slice(0, full.length - 30)), "malformed");
});

Deno.test("decodeJwtExp treats a non-numeric exp as malformed", () => {
  assertEquals(decodeJwtExp(jwt({ exp: "soon" })), "malformed");
});

Deno.test("parseGithubExpiryHeader handles GitHub's format", () => {
  // Real value observed from GET /user: "2026-11-11 23:58:42 UTC"
  const got = parseGithubExpiryHeader("2026-11-11 23:58:42 UTC");
  assertEquals(new Date((got as number) * 1000).toISOString(), "2026-11-11T23:58:42.000Z");
});

Deno.test("parseGithubExpiryHeader returns null when absent or unparseable", () => {
  assertEquals(parseGithubExpiryHeader(null), null);
  assertEquals(parseGithubExpiryHeader(""), null);
  assertEquals(parseGithubExpiryHeader("whenever"), null);
});

const policy = { warnDays: [30, 14, 7], criticalDays: 3 };

Deno.test("classify maps days onto statuses", () => {
  assertEquals(classify(90, policy), "ok");
  assertEquals(classify(31, policy), "ok");
  assertEquals(classify(30, policy), "warn");
  assertEquals(classify(4, policy), "warn");
  assertEquals(classify(3, policy), "critical");
  assertEquals(classify(0, policy), "critical");
  assertEquals(classify(-1, policy), "expired");
});

Deno.test("classify reports no-expiry as its own state, never as ok", () => {
  // Reporting this as `ok` would hide precisely the class of credential the
  // model exists because of.
  assertEquals(classify(null, policy), "noExpiry");
});

import { preflight, resourceNameFor } from "./credential_expiry.ts";

Deno.test("resourceNameFor strips characters unsafe in a storage key", () => {
  // Manifest ids are path-shaped; instance names must not be.
  assertEquals(resourceNameFor("connect-token/deploy-bot"), "connect-token-deploy-bot");
  assertEquals(resourceNameFor("pat/sweep"), "pat-sweep");
  assertEquals(resourceNameFor("already.safe_id-1"), "already.safe_id-1");
  assertEquals(resourceNameFor("/leading/and/trailing/"), "leading-and-trailing");
});

Deno.test("preflight passes a clean config", () => {
  assertEquals(
    preflight([{ id: "connect-token/a" }, { id: "pat/b" }]),
    [],
  );
});

Deno.test("preflight catches duplicate ids", () => {
  const problems = preflight([{ id: "same" }, { id: "same" }]);
  assertEquals(problems.length, 1);
  assertEquals(problems[0].includes("duplicate id"), true);
});

Deno.test("preflight catches ids that collide after normalisation", () => {
  // These differ, but both become "a-b" -- the second would silently overwrite
  // the first's resource and one credential would vanish from the audit while
  // the run still reported success.
  const problems = preflight([{ id: "a/b" }, { id: "a:b" }]);
  assertEquals(problems.length, 1);
  assertEquals(problems[0].includes("normalise to resource name"), true);
});

Deno.test("preflight rejects an id with no usable characters", () => {
  const problems = preflight([{ id: "///" }]);
  assertEquals(problems.length, 1);
  assertEquals(problems[0].includes("no usable characters"), true);
});

import { shouldNotify } from "./credential_expiry.ts";

const P = { warnDays: [30, 14, 7], criticalDays: 3 };

Deno.test("shouldNotify fires on the day a threshold is crossed, not before or after", () => {
  // The whole point: a 29-day credential is actionable for 29 days running, and
  // an alert that repeats an unchanged fact daily for a month gets filtered.
  assertEquals(shouldNotify([{ status: "warn", daysRemaining: 30 }], P).notify, true);
  assertEquals(shouldNotify([{ status: "warn", daysRemaining: 29 }], P).notify, false);
  assertEquals(shouldNotify([{ status: "warn", daysRemaining: 15 }], P).notify, false);
  assertEquals(shouldNotify([{ status: "warn", daysRemaining: 14 }], P).notify, true);
  assertEquals(shouldNotify([{ status: "warn", daysRemaining: 7 }], P).notify, true);
});

Deno.test("shouldNotify fires every day once inside criticalDays", () => {
  for (const d of [3, 2, 1, 0]) {
    assertEquals(shouldNotify([{ status: "critical", daysRemaining: d }], P).notify, true);
  }
});

Deno.test("shouldNotify always fires for outage-shaped statuses", () => {
  for (const s of ["authFailed", "expired", "unreachable"] as const) {
    const got = shouldNotify([{ status: s, daysRemaining: null }], P);
    assertEquals(got.notify, true);
    assertEquals(got.reason, s);
  }
});

Deno.test("shouldNotify stays quiet for ok and for noExpiry", () => {
  assertEquals(shouldNotify([{ status: "ok", daysRemaining: 89 }], P).notify, false);
  // noExpiry is standing design debt for a review, never a nightly page.
  assertEquals(shouldNotify([{ status: "noExpiry", daysRemaining: null }], P).notify, false);
});

Deno.test("shouldNotify reports the worst reason when several apply", () => {
  const got = shouldNotify([
    { status: "warn", daysRemaining: 30 },
    { status: "authFailed", daysRemaining: null },
  ], P);
  assertEquals(got.reason, "authFailed");
});

// --- GitLab -----------------------------------------------------------------

Deno.test("parseGitlabExpiryDate anchors a bare date to UTC midnight", () => {
  // The start of the day, not the end: an expiry monitor that is optimistic by
  // a day reports safe on the morning something has already broken.
  assertEquals(
    parseGitlabExpiryDate("2026-11-11"),
    Math.floor(Date.parse("2026-11-11T00:00:00Z") / 1000),
  );
});

Deno.test("parseGitlabExpiryDate treats a missing or unusable value as no expiry", () => {
  assertEquals(parseGitlabExpiryDate(null), null);
  assertEquals(parseGitlabExpiryDate(undefined), null);
  assertEquals(parseGitlabExpiryDate(""), null);
  assertEquals(parseGitlabExpiryDate("   "), null);
  assertEquals(parseGitlabExpiryDate("soon"), null);
  assertEquals(parseGitlabExpiryDate(1794609198), null);
});

/** Run one probe against a stubbed fetch, restoring the original after. */
function withFetch<T>(
  handler: (url: string, init: RequestInit) => Response,
  fn: () => Promise<T>,
): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch =
    ((input: string | URL | Request, init?: RequestInit) =>
      Promise.resolve(handler(String(input), init ?? {}))) as typeof fetch;
  return fn().finally(() => {
    globalThis.fetch = original;
  });
}

const GL = {
  credentials: [],
  warnDays: [30, 14, 7],
  criticalDays: 3,
  apiBaseUrl: "https://api.github.com",
  gitlabBaseUrl: "https://gitlab.example.com",
  timeoutMs: 15000,
  // deno-lint-ignore no-explicit-any
} as any;

const NOW = new Date("2026-08-19T00:00:00Z");

Deno.test("gitlab-pat reads expires_at from the self endpoint", async () => {
  let captured = { url: "", token: "" };
  const result = await withFetch(
    (url, init) => {
      captured = {
        url,
        token: (init.headers as Record<string, string>)["PRIVATE-TOKEN"],
      };
      return new Response(
        JSON.stringify({ id: 1, expires_at: "2026-09-18", active: true }),
        { status: 200 },
      );
    },
    () => Promise.resolve(probeFor("gitlab-pat")("glpat-x", GL, NOW)),
  );
  assertEquals(
    captured.url,
    "https://gitlab.example.com/api/v4/personal_access_tokens/self",
  );
  assertEquals(captured.token, "glpat-x");
  assertEquals(result.daysRemaining, 30);
  // 30 is exactly the widest warnDays threshold, and the boundary is
  // inclusive — this is the day the credential first becomes visible.
  assertEquals(result.status, "warn");
});

Deno.test("gitlab-pat treats 401 as an outage in progress", async () => {
  const result = await withFetch(
    () => new Response('{"message":"401 Unauthorized"}', { status: 401 }),
    () => Promise.resolve(probeFor("gitlab-pat")("glpat-dead", GL, NOW)),
  );
  assertEquals(result.status, "authFailed");
});

Deno.test("gitlab-pat does NOT treat 403 insufficient_scope as a dead credential", async () => {
  // A read_registry token is working exactly as intended; it just cannot look
  // at itself. Paging on this would be paging on a healthy credential.
  const result = await withFetch(
    () =>
      new Response(
        '{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided by the access token."}',
        { status: 403 },
      ),
    () => Promise.resolve(probeFor("gitlab-pat")("glpat-narrow", GL, NOW)),
  );
  assertEquals(result.status, "noExpiry");
  assertEquals(result.daysRemaining, null);
});

Deno.test("gitlab-pat reports a token with no expires_at as unmonitorable", async () => {
  const result = await withFetch(
    () =>
      new Response(JSON.stringify({ id: 1, expires_at: null, active: true }), {
        status: 200,
      }),
    () => Promise.resolve(probeFor("gitlab-pat")("glpat-forever", GL, NOW)),
  );
  assertEquals(result.status, "noExpiry");
});

Deno.test("gitlab-pat believes revoked over a future expires_at", async () => {
  // Trusting expires_at alone would report a dead credential as healthy right
  // up until its nominal expiry.
  const result = await withFetch(
    () =>
      new Response(
        JSON.stringify({ id: 1, expires_at: "2027-01-01", revoked: true }),
        { status: 200 },
      ),
    () => Promise.resolve(probeFor("gitlab-pat")("glpat-revoked", GL, NOW)),
  );
  assertEquals(result.status, "authFailed");
  assertEquals(result.daysRemaining, null);
});

Deno.test("gitlab-pat separates a network failure from a credential failure", async () => {
  const result = await withFetch(
    () => {
      throw new TypeError("connection refused");
    },
    () => Promise.resolve(probeFor("gitlab-pat")("glpat-x", GL, NOW)),
  );
  assertEquals(result.status, "unreachable");
});

Deno.test("gitlab-pat classifies an already-lapsed token as expired", async () => {
  const result = await withFetch(
    () =>
      new Response(
        JSON.stringify({ id: 1, expires_at: "2026-08-01", active: true }),
        { status: 200 },
      ),
    () => Promise.resolve(probeFor("gitlab-pat")("glpat-old", GL, NOW)),
  );
  assertEquals(result.status, "expired");
});

Deno.test("a trailing slash on gitlabBaseUrl does not double the separator", async () => {
  let url = "";
  await withFetch(
    (u) => {
      url = u;
      return new Response(JSON.stringify({ id: 1, active: true }), {
        status: 200,
      });
    },
    () =>
      Promise.resolve(
        probeFor("gitlab-pat")(
          "glpat-x",
          { ...GL, gitlabBaseUrl: "https://gitlab.example.com/" },
          NOW,
        ),
      ),
  );
  assertEquals(
    url,
    "https://gitlab.example.com/api/v4/personal_access_tokens/self",
  );
});

Deno.test("probeFor covers every declared probe kind", () => {
  // The guard against adding a kind to PROBE_KINDS with no probe behind it.
  for (const kind of PROBE_KINDS) {
    assertEquals(typeof probeFor(kind), "function");
  }
});
