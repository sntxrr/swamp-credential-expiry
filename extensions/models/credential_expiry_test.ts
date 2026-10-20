// extensions/models/credential_expiry_test.ts
import { assertEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261016.58";
import {
  AUDIT_INSTANCE,
  classify,
  type CommandRunner,
  decodeJwtExp,
  model,
  parseB2Secret,
  parseB2Subject,
  parseGithubExpiryHeader,
  parseGitlabExpiryDate,
  parseScalewaySubject,
  parseServeTokenList,
  PROBE_KINDS,
  probeFor,
  probeSwampServeToken,
  readServeTokenList,
  resolveSecret,
  type VaultLike,
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
  assertEquals(
    new Date((got as number) * 1000).toISOString(),
    "2026-11-11T23:58:42.000Z",
  );
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
  assertEquals(
    resourceNameFor("connect-token/deploy-bot"),
    "connect-token-deploy-bot",
  );
  assertEquals(resourceNameFor("pat/sweep"), "pat-sweep");
  assertEquals(resourceNameFor("already.safe_id-1"), "already.safe_id-1");
  assertEquals(
    resourceNameFor("/leading/and/trailing/"),
    "leading-and-trailing",
  );
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
  assertEquals(
    shouldNotify([{ status: "warn", daysRemaining: 30 }], P).notify,
    true,
  );
  assertEquals(
    shouldNotify([{ status: "warn", daysRemaining: 29 }], P).notify,
    false,
  );
  assertEquals(
    shouldNotify([{ status: "warn", daysRemaining: 15 }], P).notify,
    false,
  );
  assertEquals(
    shouldNotify([{ status: "warn", daysRemaining: 14 }], P).notify,
    true,
  );
  assertEquals(
    shouldNotify([{ status: "warn", daysRemaining: 7 }], P).notify,
    true,
  );
});

Deno.test("shouldNotify fires every day once inside criticalDays", () => {
  for (const d of [3, 2, 1, 0]) {
    assertEquals(
      shouldNotify([{ status: "critical", daysRemaining: d }], P).notify,
      true,
    );
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
  assertEquals(
    shouldNotify([{ status: "ok", daysRemaining: 89 }], P).notify,
    false,
  );
  // noExpiry is standing design debt for a review, never a nightly page.
  assertEquals(
    shouldNotify([{ status: "noExpiry", daysRemaining: null }], P).notify,
    false,
  );
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

import { parsePveToken } from "./credential_expiry.ts";

Deno.test("parsePveToken splits the wire format into its addressable parts", () => {
  assertEquals(parsePveToken("monitor@pve!expiry=abc-123"), {
    userid: "monitor@pve",
    tokenid: "expiry",
  });
  // a uuid secret contains no '!' or '=', so the first of each is unambiguous
  assertEquals(
    parsePveToken(
      "terraform@pve!tf-proxmox-docker=00000000-1111-2222-3333-444444444444",
    ),
    { userid: "terraform@pve", tokenid: "tf-proxmox-docker" },
  );
});

Deno.test("parsePveToken rejects anything that is not user@realm!tokenid=secret", () => {
  assertEquals(parsePveToken("no-bang-here=secret"), null);
  assertEquals(parsePveToken("missing-realm!tok=secret"), null); // no '@'
  assertEquals(parsePveToken("user@pve!=secret"), null); // empty tokenid
  assertEquals(parsePveToken("user@pve!tok"), null); // no '='
  assertEquals(parsePveToken("!tok=secret"), null); // empty userid
});

const PVE = {
  credentials: [],
  warnDays: [30, 14, 7],
  criticalDays: 3,
  apiBaseUrl: "https://api.github.com",
  gitlabBaseUrl: "https://gitlab.example.com",
  pveBaseUrl: "https://pve.example.com",
  timeoutMs: 15000,
  // deno-lint-ignore no-explicit-any
} as any;

const PVE_SECRET = "monitor@pve!expiry=00000000-1111-2222-3333-444444444444";

function pveBody(tokens: Record<string, unknown>): Response {
  return new Response(JSON.stringify({ data: { tokens } }), { status: 200 });
}

Deno.test("pve-token reads expire out of the user record, not the token endpoint", async () => {
  let seen = "";
  const res = await withFetch(
    (url) => {
      seen = url;
      // 90 days after NOW (2026-11-17T00:00:00Z), well clear of every warn
      // threshold -- this test is about the URL and the parse, not classify.
      // Note `warn` fires AT the threshold, so 30 days exactly would be `warn`.
      return pveBody({ expiry: { expire: 1_794_873_600, privsep: 1 } });
    },
    () =>
      Promise.resolve(
        probeFor("pve-token")(
          PVE_SECRET,
          PVE,
          new Date("2026-08-19T00:00:00Z"),
        ),
      ),
  );
  // the user record -- asking for /token/{id} would need User.Modify
  assertEquals(
    seen,
    "https://pve.example.com/api2/json/access/users/monitor%40pve",
  );
  assertEquals(res.status, "ok");
  assertEquals(res.expiresAt, new Date(1_794_873_600 * 1000).toISOString());
});

Deno.test("pve-token treats expire: 0 as never, not as 1970", async () => {
  const res = await withFetch(
    () => pveBody({ expiry: { expire: 0, privsep: 1 } }),
    () => Promise.resolve(probeFor("pve-token")(PVE_SECRET, PVE, NOW)),
  );
  assertEquals(res.status, "noExpiry");
  assertEquals(res.expiresAt, null);
});

Deno.test("pve-token reports a missing tokenid as an outage, never as noExpiry", async () => {
  // A deleted or renamed token read from a stale manifest. Calling this
  // "no expiry" would report a credential that cannot authenticate as healthy.
  const res = await withFetch(
    () => pveBody({ "some-other-token": { expire: 0 } }),
    () => Promise.resolve(probeFor("pve-token")(PVE_SECRET, PVE, NOW)),
  );
  assertEquals(res.status, "authFailed");
});

Deno.test("pve-token separates 401 (refused) from 403 (unmonitorable)", async () => {
  const refused = await withFetch(
    () => new Response("", { status: 401 }),
    () => Promise.resolve(probeFor("pve-token")(PVE_SECRET, PVE, NOW)),
  );
  assertEquals(refused.status, "authFailed");

  // A working token that merely lacks Sys.Audit. Paging over this would be a
  // false alarm -- same reasoning as the GitLab insufficient_scope case.
  const unmonitorable = await withFetch(
    () => new Response("", { status: 403 }),
    () => Promise.resolve(probeFor("pve-token")(PVE_SECRET, PVE, NOW)),
  );
  assertEquals(unmonitorable.status, "noExpiry");
});

Deno.test("pve-token separates a network failure from a credential failure", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (() => Promise.reject(new Error("boom"))) as typeof fetch;
  try {
    const res = await probeFor("pve-token")(PVE_SECRET, PVE, NOW);
    assertEquals(res.status, "unreachable");
  } finally {
    globalThis.fetch = original;
  }
});

Deno.test("pve-token rejects a malformed secret before making a request", async () => {
  let called = false;
  const res = await withFetch(
    () => {
      called = true;
      return pveBody({});
    },
    () => Promise.resolve(probeFor("pve-token")("not-a-pve-token", PVE, NOW)),
  );
  assertEquals(res.status, "authFailed");
  assertEquals(called, false);
});

Deno.test("a trailing slash on pveBaseUrl does not double the separator", async () => {
  let seen = "";
  await withFetch(
    (url) => {
      seen = url;
      return pveBody({ expiry: { expire: 0 } });
    },
    () =>
      Promise.resolve(
        probeFor("pve-token")(PVE_SECRET, {
          ...PVE,
          pveBaseUrl: "https://pve.example.com/",
        }, NOW),
      ),
  );
  assertEquals(
    seen,
    "https://pve.example.com/api2/json/access/users/monitor%40pve",
  );
});

Deno.test("pve-token treats a non-JSON 2xx body as unreachable, not as a credential fault", async () => {
  const res = await withFetch(
    () => new Response("<html>proxy error</html>", { status: 200 }),
    () => Promise.resolve(probeFor("pve-token")(PVE_SECRET, PVE, NOW)),
  );
  // A reverse proxy answering 200 with an error page must not read as "expired"
  // or "authFailed" -- neither says anything true about the credential.
  assertEquals(res.status, "unreachable");
});

Deno.test("pve-token treats a non-numeric expire as noExpiry rather than trusting it", async () => {
  const res = await withFetch(
    () => pveBody({ expiry: { expire: "1794873600" } }),
    () => Promise.resolve(probeFor("pve-token")(PVE_SECRET, PVE, NOW)),
  );
  assertEquals(res.status, "noExpiry");
  assertEquals(res.daysRemaining, null);
});

import { parsePveSubject } from "./credential_expiry.ts";

Deno.test("parsePveSubject accepts an identifier and rejects a pasted secret", () => {
  assertEquals(parsePveSubject("terraform@pve!tf-proxmox-docker"), {
    userid: "terraform@pve",
    tokenid: "tf-proxmox-docker",
  });
  // A subject carrying '=' is a SECRET where an identifier belongs. Accepting it
  // would write credential material into a resource attribute.
  assertEquals(
    parsePveSubject("terraform@pve!tok=00000000-1111-2222-3333-444444444444"),
    null,
  );
  assertEquals(parsePveSubject("no-realm!tok"), null);
  assertEquals(parsePveSubject("user@pve!"), null);
  assertEquals(parsePveSubject("user@pve"), null);
});

Deno.test("pve-token with a subject reports the SUBJECT's expiry, not its own", async () => {
  // The regression this field exists for: authenticating as the monitor while
  // reporting on the provisioning token. Reading the monitor's own row here
  // would report `noExpiry` for a credential that actually lapses.
  let seen = "";
  const res = await withFetch(
    (url) => {
      seen = url;
      return pveBody({
        expiry: { expire: 0 }, // the authenticating token -- never expires
        "tf-proxmox-docker": { expire: 1_794_873_600 }, // the subject
      });
    },
    () =>
      Promise.resolve(
        probeFor("pve-token")(
          PVE_SECRET,
          PVE,
          NOW,
          "terraform@pve!tf-proxmox-docker",
        ),
      ),
  );
  // looked up the SUBJECT's user, not monitor@pve
  assertEquals(
    seen,
    "https://pve.example.com/api2/json/access/users/terraform%40pve",
  );
  assertEquals(res.status, "ok");
  assertEquals(res.expiresAt, new Date(1_794_873_600 * 1000).toISOString());
  // and says whose expiry it is
  assertEquals(
    res.detail.includes("on behalf of terraform@pve!tf-proxmox-docker"),
    true,
  );
});

Deno.test("pve-token with no subject still reports its own expiry", async () => {
  const res = await withFetch(
    () => pveBody({ expiry: { expire: 1_794_873_600 } }),
    () => Promise.resolve(probeFor("pve-token")(PVE_SECRET, PVE, NOW)),
  );
  assertEquals(res.status, "ok");
  assertEquals(res.detail.includes("on behalf of"), false);
});

Deno.test("pve-token rejects a malformed subject without falling back to self", async () => {
  // Falling back would silently report the WRONG credential as healthy.
  const res = await withFetch(
    () => pveBody({ expiry: { expire: 0 } }),
    () =>
      Promise.resolve(probeFor("pve-token")(PVE_SECRET, PVE, NOW, "garbage")),
  );
  assertEquals(res.status, "authFailed");
});

Deno.test("pve-token reports a subject missing from its user as authFailed", async () => {
  const res = await withFetch(
    () => pveBody({ "some-other": { expire: 0 } }),
    () =>
      Promise.resolve(
        probeFor("pve-token")(
          PVE_SECRET,
          PVE,
          NOW,
          "terraform@pve!tf-proxmox-docker",
        ),
      ),
  );
  assertEquals(res.status, "authFailed");
});

// ---------------------------------------------------------------------------
// b2-key
// ---------------------------------------------------------------------------

const B2 = {
  credentials: [],
  warnDays: [30, 14, 7],
  criticalDays: 3,
  apiBaseUrl: "https://api.github.com",
  gitlabBaseUrl: "https://gitlab.example.com",
  pveBaseUrl: "https://pve.example.com",
  b2BaseUrl: "https://api.backblazeb2.com",
  scwBaseUrl: "https://api.scaleway.com",
  swampBin: "swamp",
  swampRepoDir: "",
  timeoutMs: 15000,
};
const B2_SECRET = "002abc0123456780000000099:K002aaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B2_KEYID = "002abc0123456780000000099";

/** Route the two-call B2 flow: authorize, then list_keys. */
function b2Fetch(
  keys: unknown[],
  opts: { capabilities?: string[]; authStatus?: number } = {},
) {
  return (url: string): Response => {
    if (url.includes("b2_authorize_account")) {
      if (opts.authStatus && opts.authStatus !== 200) {
        return new Response("", { status: opts.authStatus });
      }
      return new Response(
        JSON.stringify({
          accountId: "abc012345678",
          authorizationToken: "4_token",
          apiInfo: {
            storageApi: {
              apiUrl: "https://api002.backblazeb2.com",
              capabilities: opts.capabilities ?? ["listKeys", "listBuckets"],
            },
          },
        }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify({ keys }), { status: 200 });
  };
}

Deno.test("b2-key reads expirationTimestamp in MILLISECONDS, not seconds", async () => {
  // The single most dangerous unit bug available here: B2 reports ms where
  // Proxmox reports seconds. Treating ms as seconds puts the expiry ~50,000
  // years out and classifies a key about to lapse as `ok`.
  const expMs = Date.UTC(2026, 10, 17, 0, 0, 0); // 2026-11-17
  const res = await withFetch(
    b2Fetch([{ applicationKeyId: B2_KEYID, expirationTimestamp: expMs }]),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.expiresAt, new Date(expMs).toISOString());
  assertEquals(res.daysRemaining, 90);
  assertEquals(res.status, "ok");
});

Deno.test("b2-key treats a missing listKeys capability as a monitoring gap, not an outage", async () => {
  // B2 answers 401 both for a refused key and for a good key lacking the
  // capability. Reading the capability from the authorize response is what
  // keeps those apart -- one is an outage, the other is not worth paging for.
  const res = await withFetch(
    b2Fetch([], { capabilities: ["listBuckets", "readFiles"] }),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "noExpiry");
  assertEquals(res.detail.includes("lacks the listKeys capability"), true);
});

Deno.test("b2-key reports a refused key as authFailed", async () => {
  const res = await withFetch(
    b2Fetch([], { authStatus: 401 }),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "authFailed");
});

Deno.test("b2-key reports a key missing from the account as an outage, never as noExpiry", async () => {
  // An EXPIRED B2 key is deleted outright rather than kept and flagged, so
  // "absent" is the shape a lapse actually takes. Calling it noExpiry would
  // report a dead credential as a standing design debt.
  const res = await withFetch(
    b2Fetch([{
      applicationKeyId: "002somethingelse",
      expirationTimestamp: null,
    }]),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "authFailed");
  assertEquals(
    res.detail.includes("deleted, expired, or the manifest is stale"),
    true,
  );
});

Deno.test("b2-key treats a null expirationTimestamp as noExpiry", async () => {
  const res = await withFetch(
    b2Fetch([{ applicationKeyId: B2_KEYID, expirationTimestamp: null }]),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "noExpiry");
});

Deno.test("b2-key with a subject reports the SUBJECT's key, not its own", async () => {
  let listUrl = "";
  const expMs = Date.UTC(2026, 10, 17);
  const res = await withFetch(
    (url) => {
      if (url.includes("b2_list_keys")) listUrl = url;
      return b2Fetch([{
        applicationKeyId: "002othertarget",
        expirationTimestamp: expMs,
      }])(url);
    },
    () =>
      Promise.resolve(
        probeFor("b2-key")(B2_SECRET, B2, NOW, "002othertarget"),
      ),
  );
  assertEquals(listUrl.includes("startApplicationKeyId=002othertarget"), true);
  assertEquals(res.status, "ok");
  assertEquals(res.detail.includes("on behalf of 002othertarget"), true);
});

Deno.test("b2-key rejects a malformed secret before making a request", async () => {
  let called = false;
  const res = await withFetch(
    () => {
      called = true;
      return new Response("{}", { status: 200 });
    },
    () => Promise.resolve(probeFor("b2-key")("no-colon-here", B2, NOW)),
  );
  assertEquals(res.status, "authFailed");
  assertEquals(called, false);
});

Deno.test("parseB2Secret and parseB2Subject reject a secret pasted as an identifier", () => {
  assertEquals(parseB2Secret("abc:def"), { keyId: "abc", appKey: "def" });
  assertEquals(parseB2Secret("abc"), null);
  assertEquals(parseB2Secret("abc:def:ghi"), null);
  // a subject must be a bare id -- never a key pair
  assertEquals(parseB2Subject("002abc"), "002abc");
  assertEquals(parseB2Subject("002abc:K002secret"), null);
  assertEquals(parseB2Subject(""), null);
});

Deno.test("a trailing slash on b2BaseUrl does not double the separator", async () => {
  let seen = "";
  await withFetch(
    (url) => {
      if (url.includes("b2_authorize_account")) seen = url;
      return b2Fetch([{
        applicationKeyId: B2_KEYID,
        expirationTimestamp: null,
      }])(url);
    },
    () =>
      Promise.resolve(
        probeFor("b2-key")(B2_SECRET, {
          ...B2,
          b2BaseUrl: "https://api.backblazeb2.com/",
        }, NOW),
      ),
  );
  assertEquals(
    seen,
    "https://api.backblazeb2.com/b2api/v3/b2_authorize_account",
  );
});

Deno.test("b2-key treats a non-401 authorize failure as unreachable, not as a credential fault", async () => {
  // A 500 from Backblaze is their outage, not our credential's. Reporting it as
  // authFailed would page someone to rotate a key that is perfectly good.
  const res = await withFetch(
    b2Fetch([], { authStatus: 503 }),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "unreachable");
});

Deno.test("b2-key treats a non-JSON authorize body as unreachable", async () => {
  // A captive portal or proxy returning HTML with a 200. Parsing must not throw
  // out of the probe and take the whole audit down with it.
  const res = await withFetch(
    () => new Response("<html>proxy</html>", { status: 200 }),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "unreachable");
});

Deno.test("b2-key treats an authorize response missing apiUrl as unreachable", async () => {
  // Well-formed JSON that is not the contract. Proceeding would build a request
  // against `undefined` and fail somewhere less legible.
  const res = await withFetch(
    () =>
      new Response(
        JSON.stringify({ accountId: "abc012345678", authorizationToken: "t" }),
        { status: 200 },
      ),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "unreachable");
});

Deno.test("b2-key separates a network failure from a credential failure", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (() => Promise.reject(new Error("boom"))) as typeof fetch;
  try {
    const res = await probeFor("b2-key")(B2_SECRET, B2, NOW);
    assertEquals(res.status, "unreachable");
  } finally {
    globalThis.fetch = original;
  }
});

Deno.test("b2-key treats a failed b2_list_keys as unreachable, never as noExpiry", async () => {
  // The dangerous alternative: a key whose expiry could not be READ must not be
  // reported as a key that HAS no expiry. Those look identical in a summary and
  // mean opposite things.
  const res = await withFetch(
    (url) =>
      url.includes("b2_list_keys")
        ? new Response("", { status: 500 })
        : b2Fetch([])(url),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "unreachable");
});

Deno.test("b2-key treats a non-JSON b2_list_keys body as unreachable", async () => {
  const res = await withFetch(
    (url) =>
      url.includes("b2_list_keys")
        ? new Response("not json", { status: 200 })
        : b2Fetch([])(url),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(res.status, "unreachable");
});

// ---------------------------------------------------------------------------
// scaleway-key
// ---------------------------------------------------------------------------

const SCW = B2;
const SCW_SECRET = "00000000-1111-2222-3333-444444444444";
const SCW_SUBJECT = "SCWEXAMPLEKEY0000001";

/** Answer the single IAM api-keys GET with a status and optional body. */
function scwFetch(status: number, body?: Record<string, unknown>) {
  return (): Response =>
    new Response(body === undefined ? "" : JSON.stringify(body), { status });
}

Deno.test("scaleway-key reads expires_at and classifies it", async () => {
  let seenUrl = "";
  let seenToken: string | null = null;
  const res = await withFetch(
    (url, init) => {
      seenUrl = url;
      seenToken = new Headers(init.headers).get("X-Auth-Token");
      return scwFetch(200, {
        access_key: SCW_SUBJECT,
        expires_at: "2026-11-17T00:00:00Z",
      })();
    },
    () =>
      Promise.resolve(
        probeFor("scaleway-key")(SCW_SECRET, SCW, NOW, SCW_SUBJECT),
      ),
  );
  assertEquals(
    seenUrl,
    `https://api.scaleway.com/iam/v1alpha1/api-keys/${SCW_SUBJECT}`,
  );
  assertEquals(seenToken, SCW_SECRET);
  assertEquals(res.expiresAt, "2026-11-17T00:00:00.000Z");
  assertEquals(res.daysRemaining, 90);
  assertEquals(res.status, "ok");
});

Deno.test("scaleway-key crosses the warn and critical thresholds", async () => {
  const at = (iso: string) =>
    withFetch(
      scwFetch(200, { access_key: SCW_SUBJECT, expires_at: iso }),
      () =>
        Promise.resolve(
          probeFor("scaleway-key")(SCW_SECRET, SCW, NOW, SCW_SUBJECT),
        ),
    );
  assertEquals((await at("2026-09-02T00:00:00Z")).status, "warn"); // 14 days
  assertEquals((await at("2026-08-21T00:00:00Z")).status, "critical"); // 2 days
  assertEquals((await at("2026-08-18T00:00:00Z")).status, "expired");
});

Deno.test("scaleway-key treats a null expires_at as noExpiry", async () => {
  // An owner-attached key minted without an expiry. It must be SEEN -- the
  // whole point is that an eternal key shows up as a standing finding.
  const res = await withFetch(
    scwFetch(200, { access_key: SCW_SUBJECT, expires_at: null }),
    () =>
      Promise.resolve(
        probeFor("scaleway-key")(SCW_SECRET, SCW, NOW, SCW_SUBJECT),
      ),
  );
  assertEquals(res.status, "noExpiry");
  assertEquals(res.expiresAt, null);
});

Deno.test("scaleway-key reports a refused probe secret as authFailed", async () => {
  const res = await withFetch(
    scwFetch(401, { message: "authentication is denied" }),
    () =>
      Promise.resolve(
        probeFor("scaleway-key")(SCW_SECRET, SCW, NOW, SCW_SUBJECT),
      ),
  );
  assertEquals(res.status, "authFailed");
});

Deno.test("scaleway-key treats a 403 as a monitoring gap, not an outage", async () => {
  // A scoped key (e.g. send-only mail) authenticates fine but cannot read IAM.
  // That is a misconfigured PROBE, not a dying credential, and must not page
  // anyone to rotate a key that works.
  const res = await withFetch(
    scwFetch(403, { message: "insufficient permissions" }),
    () =>
      Promise.resolve(
        probeFor("scaleway-key")(SCW_SECRET, SCW, NOW, SCW_SUBJECT),
      ),
  );
  assertEquals(res.status, "noExpiry");
  assertEquals(res.detail.includes("403"), true);
});

Deno.test("scaleway-key reports a key missing from the organization as an outage, never as noExpiry", async () => {
  // A watched key that was deleted, or a manifest pointing at a key that never
  // existed. Either way whatever holds it is broken or the inventory is wrong.
  const res = await withFetch(
    scwFetch(404, { message: "resource is not found" }),
    () =>
      Promise.resolve(
        probeFor("scaleway-key")(SCW_SECRET, SCW, NOW, SCW_SUBJECT),
      ),
  );
  assertEquals(res.status, "authFailed");
  assertEquals(res.detail.includes(SCW_SUBJECT), true);
});

Deno.test("scaleway-key treats a 5xx as unreachable, not as a credential fault", async () => {
  const res = await withFetch(
    scwFetch(503),
    () =>
      Promise.resolve(
        probeFor("scaleway-key")(SCW_SECRET, SCW, NOW, SCW_SUBJECT),
      ),
  );
  assertEquals(res.status, "unreachable");
});

Deno.test("scaleway-key treats a non-JSON or wrong-key body as unreachable", async () => {
  const run = (h: () => Response) =>
    withFetch(
      h,
      () =>
        Promise.resolve(
          probeFor("scaleway-key")(SCW_SECRET, SCW, NOW, SCW_SUBJECT),
        ),
    );
  assertEquals(
    (await run(() => new Response("<html>proxy</html>", { status: 200 })))
      .status,
    "unreachable",
  );
  assertEquals(
    (await run(
      scwFetch(200, {
        access_key: "SCWSOMEOTHERKEY00001",
        expires_at: "2026-11-17T00:00:00Z",
      }),
    )).status,
    "unreachable",
  );
  assertEquals(
    (await run(scwFetch(200, { access_key: SCW_SUBJECT, expires_at: "soon" })))
      .status,
    "unreachable",
  );
});

Deno.test("scaleway-key separates a network failure from a credential failure", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (() => Promise.reject(new Error("boom"))) as typeof fetch;
  try {
    const res = await probeFor("scaleway-key")(
      SCW_SECRET,
      SCW,
      NOW,
      SCW_SUBJECT,
    );
    assertEquals(res.status, "unreachable");
  } finally {
    globalThis.fetch = original;
  }
});

Deno.test("scaleway-key refuses a missing subject, a bad subject or a bad secret before any request", async () => {
  // A Scaleway secret does not name its own access key, so there is nothing to
  // fall back to. And a subject is written into resources in clear, so a secret
  // pasted there must be refused, not probed.
  let called = 0;
  const run = (secret: string, subject?: string) =>
    withFetch(
      () => {
        called++;
        return scwFetch(500)();
      },
      () =>
        Promise.resolve(
          probeFor("scaleway-key")(secret, SCW, NOW, subject),
        ),
    );
  const noSubject = await run(SCW_SECRET);
  assertEquals(noSubject.status, "authFailed");
  assertEquals(noSubject.detail.includes("required"), true);
  assertEquals((await run(SCW_SECRET, SCW_SECRET)).status, "authFailed");
  assertEquals(
    (await run("SCWEXAMPLEKEY0000001", SCW_SUBJECT)).status,
    "authFailed",
  );
  assertEquals(called, 0);
});

Deno.test("parseScalewaySubject accepts only an access key id", () => {
  assertEquals(parseScalewaySubject(SCW_SUBJECT), SCW_SUBJECT);
  assertEquals(parseScalewaySubject(""), null);
  assertEquals(parseScalewaySubject(SCW_SECRET), null);
  assertEquals(parseScalewaySubject("scwexamplekey0000001"), null);
  assertEquals(parseScalewaySubject("SCWEXAMPLEKEY00000012"), null);
});

Deno.test("scaleway-key tolerates a trailing slash on scwBaseUrl", async () => {
  let seen = "";
  await withFetch(
    (url) => {
      seen = url;
      return scwFetch(200, { access_key: SCW_SUBJECT, expires_at: null })();
    },
    () =>
      Promise.resolve(
        probeFor("scaleway-key")(
          SCW_SECRET,
          { ...SCW, scwBaseUrl: "https://api.scaleway.com/" },
          NOW,
          SCW_SUBJECT,
        ),
      ),
  );
  assertEquals(
    seen,
    `https://api.scaleway.com/iam/v1alpha1/api-keys/${SCW_SUBJECT}`,
  );
});

// --- secretRef: per-entry resolution ------------------------------------------

/** A vault holding exactly `items`; anything else fails like a missing item. */
function fakeVault(
  items: Record<string, string>,
): VaultLike & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    get: (vaultName: string, key: string) => {
      reads.push(`${vaultName}/${key}`);
      const v = items[`${vaultName}/${key}`];
      return v === undefined
        ? Promise.reject(
          new Error(`could not read secret '${key}': Found 0 item(s) in vault`),
        )
        : Promise.resolve(v);
    },
  };
}

Deno.test("resolveSecret passes an inline secret through without touching the vault", async () => {
  const vault = fakeVault({});
  assertEquals(await resolveSecret({ secret: "abc" }, vault), {
    secret: "abc",
  });
  assertEquals(vault.reads, []);
});

Deno.test("resolveSecret reads a secretRef and registers the value for redaction", async () => {
  const redacted: string[] = [];
  const got = await resolveSecret(
    { secretRef: { vault: "store", key: "bot/token" } },
    fakeVault({ "store/bot/token": "s3cr3t" }),
    { addSecret: (v) => redacted.push(v) },
  );
  assertEquals(got, { secret: "s3cr3t" });
  assertEquals(redacted, ["s3cr3t"]);
});

Deno.test("resolveSecret turns a missing item into a detail, never a throw", async () => {
  const got = await resolveSecret(
    { secretRef: { vault: "store", key: "gone/token" } },
    fakeVault({}),
  );
  assertEquals("detail" in got, true);
  const detail = (got as { detail: string }).detail;
  assertEquals(detail.startsWith("could not read store/gone/token: "), true);
  assertEquals(detail.includes("Found 0 item(s)"), true);
});

Deno.test("resolveSecret treats an empty read as a failure, not a pass", async () => {
  assertEquals(
    await resolveSecret(
      { secretRef: { vault: "store", key: "bot/token" } },
      fakeVault({ "store/bot/token": "" }),
    ),
    { detail: "store/bot/token resolved to an empty value" },
  );
});

Deno.test("resolveSecret reports a missing vault service rather than crashing", async () => {
  assertEquals(
    await resolveSecret({ secretRef: { vault: "store", key: "k" } }, undefined),
    { detail: "no vault service available to read store/k" },
  );
});

Deno.test("resolveSecret caps a long vault error", async () => {
  const vault: VaultLike = {
    get: () => Promise.reject(new Error("x".repeat(5000))),
  };
  const got = await resolveSecret(
    { secretRef: { vault: "v", key: "k" } },
    vault,
  );
  assertEquals((got as { detail: string }).detail.length, 300);
});

Deno.test("an entry must set exactly one of secret and secretRef", () => {
  const parse = (c: Record<string, unknown>) =>
    model.globalArguments.safeParse({
      credentials: [{ id: "a", kind: "jwt", ...c }],
    })
      .success;
  assertEquals(parse({ secret: "x" }), true);
  assertEquals(parse({ secretRef: { vault: "v", key: "k" } }), true);
  assertEquals(parse({}), false);
  assertEquals(
    parse({ secret: "x", secretRef: { vault: "v", key: "k" } }),
    false,
  );
});

Deno.test("audit: one unreadable secretRef is that entry's finding; every other entry is still probed", async () => {
  const future = Math.floor(Date.now() / 1000) + 200 * 86_400;
  const resolvedJwt = jwt({ exp: future, jti: "from-the-vault" });
  const redacted: string[] = [];
  const { context, getWrittenResources, getLogsByLevel } =
    createModelTestContext({
      methodName: "audit",
      globalArgs: model.globalArguments.parse({
        credentials: [
          { id: "inline/one", kind: "jwt", secret: jwt({ exp: future }) },
          {
            id: "missing/two",
            kind: "jwt",
            secretRef: { vault: "store", key: "gone/token" },
          },
          {
            id: "ref/three",
            kind: "jwt",
            secretRef: { vault: "store", key: "bot/token" },
          },
        ],
      }),
    });
  await model.methods.audit.execute(
    {} as Record<string, never>,
    {
      ...context,
      vaultService: fakeVault({ "store/bot/token": resolvedJwt }),
      redactor: { addSecret: (v: string) => redacted.push(v) },
    } as unknown as Parameters<typeof model.methods.audit.execute>[1],
  );

  const written = Object.fromEntries(
    getWrittenResources().map((r) => [r.name, r.data]),
  );
  assertEquals(written["inline-one"].status, "ok");
  assertEquals(written["ref-three"].status, "ok");
  assertEquals(written["missing-two"].status, "unresolved");
  assertEquals(written["missing-two"].daysRemaining, null);
  assertEquals(redacted, [resolvedJwt]);

  const audit = written[AUDIT_INSTANCE];
  assertEquals(audit.total, 3);
  assertEquals(audit.ok, 2);
  assertEquals(audit.unresolved, 1);
  assertEquals(audit.authFailed, 0);
  assertEquals(audit.actionable, true);
  assertEquals(audit.notifyToday, true);
  assertEquals(audit.notifyReason, "unresolved");
  assertEquals(
    String(audit.summary).startsWith(
      "UNRESOLVED missing/two — could not read store/gone/token",
    ),
    true,
  );
  assertEquals(getLogsByLevel("warning").length, 1);

  // Nothing written or logged may carry a vault-read value.
  const blob = JSON.stringify([
    getWrittenResources(),
    getLogsByLevel("info"),
    getLogsByLevel("warning"),
  ]);
  assertEquals(blob.includes(resolvedJwt), false);
});

Deno.test("shouldNotify treats unresolved as outage-shaped", () => {
  assertEquals(
    shouldNotify([{ status: "unresolved", daysRemaining: null }], {
      warnDays: [30, 14, 7],
      criticalDays: 3,
    }),
    { notify: true, reason: "unresolved" },
  );
});

Deno.test("secret stays marked sensitive through .optional()", () => {
  // Each zod wrapper carries its own metadata. Marking only the inner string
  // left the field's outer schema without the flag (caught in review).
  const cred = (model.globalArguments.shape.credentials as unknown as {
    element: { shape: Record<string, { meta: () => Record<string, unknown> }> };
  }).element;
  assertEquals(cred.shape.secret.meta()?.sensitive, true);
});

Deno.test("preflight refuses an id that would overwrite the audit summary", () => {
  assertEquals(
    preflight([{ id: "current" }]),
    [`id "current" normalises to "${AUDIT_INSTANCE}", which the audit summary uses`],
  );
  assertEquals(preflight([{ id: "/current/" }]).length, 1);
  assertEquals(preflight([{ id: "current-token" }]), []);
});

/** A response whose body records whether it was released. */
function trackedResponse(status: number, body = "{}") {
  const state = { released: false };
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(new TextEncoder().encode(body));
      c.close();
    },
    cancel() {
      state.released = true;
    },
  });
  const res = new Response(stream, { status });
  return { res, state };
}

Deno.test("every probe releases a response body it does not read", async () => {
  const cases: Array<[string, ProbeKindName, string, number]> = [
    ["github 200", "github-pat", "ghp_x", 200],
    ["github 401", "github-pat", "ghp_x", 401],
    ["github 500", "github-pat", "ghp_x", 500],
    ["gitlab 401", "gitlab-pat", "glpat-x", 401],
    ["gitlab 403", "gitlab-pat", "glpat-x", 403],
    ["gitlab 500", "gitlab-pat", "glpat-x", 500],
    ["pve 401", "pve-token", PVE_SECRET, 401],
    ["pve 403", "pve-token", PVE_SECRET, 403],
    ["pve 500", "pve-token", PVE_SECRET, 500],
    ["b2 authorize 401", "b2-key", B2_SECRET, 401],
    ["b2 authorize 500", "b2-key", B2_SECRET, 500],
  ];
  for (const [name, kind, secret, status] of cases) {
    const t = trackedResponse(status);
    await withFetch(
      () => t.res,
      () =>
        Promise.resolve(probeFor(kind)(secret, { ...GL, ...PVE, ...B2 }, NOW)),
    );
    assertEquals(t.state.released || t.res.bodyUsed, true, name);
  }

  // b2_list_keys failing after a good authorize.
  const list = trackedResponse(500);
  const auth = b2Fetch([]);
  await withFetch(
    (url) => url.includes("b2_list_keys") ? list.res : auth(url),
    () => Promise.resolve(probeFor("b2-key")(B2_SECRET, B2, NOW)),
  );
  assertEquals(list.state.released || list.res.bodyUsed, true, "b2 list 500");
});

type ProbeKindName = typeof PROBE_KINDS[number];

// --- swamp-serve-token ----------------------------------------------------------

/** A listing as `swamp access token list --json` prints it (fictional tokens). */
function serveRow(
  name: string,
  expiresAt: string | null,
  effectiveState = "active",
): Record<string, unknown> {
  return {
    name,
    principalId: `user:${name}`,
    principalEmail: null,
    state: effectiveState,
    effectiveState,
    createdAt: "2026-08-01T00:00:00.000Z",
    expiresAt,
  };
}

const SERVE_LIST = JSON.stringify([
  serveRow("report-bot", "2026-11-18T12:00:00.000Z"),
  serveRow("old-bot", "2026-12-01T00:00:00.000Z", "revoked"),
  serveRow("lapsed-bot", "2026-08-01T00:00:00.000Z", "expired"),
  serveRow("forever-bot", null),
]);

const serveListing = () => parseServeTokenList(SERVE_LIST);

Deno.test("swamp-serve-token reads expiresAt for the named token", () => {
  assertEquals(
    probeSwampServeToken("report-bot", serveListing(), NOW, policy),
    {
      status: "ok",
      expiresAt: "2026-11-18T12:00:00.000Z",
      daysRemaining: 91,
      detail: "",
    },
  );
});

Deno.test("swamp-serve-token reports a token missing from the listing as an outage, never as silence", () => {
  const r = probeSwampServeToken("no-such-bot", serveListing(), NOW, policy);
  assertEquals(r.status, "authFailed");
  assertEquals(r.daysRemaining, null);
  assertEquals(r.detail.startsWith("no server token 'no-such-bot'"), true);
});

Deno.test("swamp-serve-token treats a revoked token as authFailed despite a future expiresAt", () => {
  const r = probeSwampServeToken("old-bot", serveListing(), NOW, policy);
  assertEquals(r.status, "authFailed");
  assertEquals(r.detail, "server token 'old-bot' is revoked, not active");
});

Deno.test("swamp-serve-token reports a lapsed token as expired", () => {
  const r = probeSwampServeToken("lapsed-bot", serveListing(), NOW, policy);
  assertEquals(r.status, "expired");
  assertEquals(r.daysRemaining, -18);
});

Deno.test("swamp-serve-token treats a null expiresAt as noExpiry", () => {
  assertEquals(
    probeSwampServeToken("forever-bot", serveListing(), NOW, policy).status,
    "noExpiry",
  );
});

Deno.test("swamp-serve-token refuses a missing subject or a pasted token before looking anything up", () => {
  assertEquals(
    probeSwampServeToken(undefined, serveListing(), NOW, policy).detail,
    "`subject` is required for swamp-serve-token: it names the server token",
  );
  const pasted = probeSwampServeToken(
    "report-bot.0123456789abcdef",
    serveListing(),
    NOW,
    policy,
  );
  assertEquals(pasted.status, "authFailed");
  assertEquals(pasted.detail.includes("0123456789abcdef"), false);
});

Deno.test("swamp-serve-token reports an unreadable listing as unreachable, not as a missing token", () => {
  const r = probeSwampServeToken(
    "report-bot",
    { detail: "swamp exited 1: boom" },
    NOW,
    policy,
  );
  assertEquals(r.status, "unreachable");
  assertEquals(r.detail, "swamp exited 1: boom");
});

Deno.test("parseServeTokenList refuses output that is not an array of named rows", () => {
  assertEquals("detail" in parseServeTokenList("not json"), true);
  assertEquals("detail" in parseServeTokenList("{}"), true);
  assertEquals("detail" in parseServeTokenList("[{}]"), true);
  assertEquals(parseServeTokenList("[]"), { tokens: [] });
});

Deno.test("parseServeTokenList keeps only metadata fields", () => {
  const got = parseServeTokenList(
    JSON.stringify([{ ...serveRow("report-bot", null), extra: "x" }]),
  );
  assertEquals(got, {
    tokens: [{
      name: "report-bot",
      state: "active",
      effectiveState: "active",
      expiresAt: null,
    }],
  });
});

Deno.test("readServeTokenList runs the CLI with --repo-dir and turns failures into a detail", async () => {
  const calls: string[][] = [];
  const ok: CommandRunner = (argv) => {
    calls.push(argv);
    return Promise.resolve({ code: 0, stdout: SERVE_LIST, stderr: "" });
  };
  const got = await readServeTokenList(
    { swampBin: "swamp", swampRepoDir: "/srv/repo", timeoutMs: 1000 },
    ok,
  );
  assertEquals("tokens" in got && got.tokens.length, 4);
  assertEquals(calls, [[
    "swamp",
    "access",
    "token",
    "list",
    "--json",
    "--repo-dir",
    "/srv/repo",
  ]]);

  const failed = await readServeTokenList(
    { swampBin: "swamp", swampRepoDir: "", timeoutMs: 1000 },
    () => Promise.resolve({ code: 1, stdout: "", stderr: "no repo here" }),
  );
  assertEquals(failed, {
    detail: "swamp access token list --json exited 1: no repo here",
  });

  const missing = await readServeTokenList(
    { swampBin: "swamp", swampRepoDir: "", timeoutMs: 1000 },
    () => Promise.reject(new Error("NotFound: swamp")),
  );
  assertEquals(
    "detail" in missing && missing.detail.startsWith("could not run swamp"),
    true,
  );
});

Deno.test("a swamp-serve-token entry takes no secret and needs no vault", () => {
  const parse = (c: Record<string, unknown>) =>
    model.globalArguments.safeParse({
      credentials: [{
        id: "a",
        kind: "swamp-serve-token",
        subject: "report-bot",
        ...c,
      }],
    }).success;
  assertEquals(parse({}), true);
  assertEquals(parse({ secret: "x" }), false);
  assertEquals(parse({ secretRef: { vault: "v", key: "k" } }), false);
});

Deno.test("audit: serve-token entries share one listing and never touch the vault", async () => {
  let listings = 0;
  const vault = fakeVault({});
  const { context, getWrittenResources } = createModelTestContext({
    methodName: "audit",
    globalArgs: model.globalArguments.parse({
      credentials: [
        {
          id: "serve/report-bot",
          kind: "swamp-serve-token",
          subject: "report-bot",
        },
        {
          id: "serve/no-such-bot",
          kind: "swamp-serve-token",
          subject: "no-such-bot",
        },
      ],
    }),
  });
  // Stub the CLI at the probe's seam: the audit reads it through probeFor's deps.
  const original = Deno.Command;
  // deno-lint-ignore no-explicit-any
  (Deno as any).Command = class {
    output() {
      listings += 1;
      return Promise.resolve({
        code: 0,
        stdout: new TextEncoder().encode(SERVE_LIST),
        stderr: new Uint8Array(),
      });
    }
  };
  try {
    await model.methods.audit.execute(
      {} as Record<string, never>,
      { ...context, vaultService: vault } as unknown as Parameters<
        typeof model.methods.audit.execute
      >[1],
    );
  } finally {
    // deno-lint-ignore no-explicit-any
    (Deno as any).Command = original;
  }

  const written = Object.fromEntries(
    getWrittenResources().map((r) => [r.name, r.data]),
  );
  assertEquals(listings, 1);
  assertEquals(vault.reads, []);
  assertEquals(written["serve-report-bot"].kind, "swamp-serve-token");
  assertEquals(typeof written["serve-report-bot"].daysRemaining, "number");
  assertEquals(written["serve-no-such-bot"].status, "authFailed");
  assertEquals(written[AUDIT_INSTANCE].authFailed, 1);
});
