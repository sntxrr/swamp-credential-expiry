/**
 * Credential expiry — probe the credentials an automation fleet actually holds
 * and report how long each has left.
 *
 * The problem is not "credentials expire". It is that expiry is invisible until
 * something stops working, and the thing that stops working is usually the
 * unattended job nobody watches. On the fleet this was built against, three
 * credentials were due to lapse inside a two-day window in November and every
 * one of them would have failed silently: a weekly dependency sweep whose alert
 * only fires on success, an archive job that resolves its storage keys at run
 * time, and a token with no expiry claim at all that was therefore invisible to
 * every clock.
 *
 * Four decisions worth reading before use:
 *
 * 1. **Probe the credential the CONSUMER holds, not a registry.** Asking the
 *    provider "which tokens exist?" answers a different question, needs
 *    privileges the consumer does not have, and cannot see a deployment left
 *    behind on a superseded credential. Handing this model the same secret the
 *    job uses means a stale consumer shows up as its own finding.
 *
 * 2. **`no-expiry` is a state, not a pass.** A credential with no expiry is not
 *    healthy; it is unmonitorable, which is strictly worse than one that is
 *    about to lapse. Reporting it as `ok` would hide exactly the class of
 *    credential this model exists because of. It gets its own status and is
 *    counted separately.
 *
 * 3. **An authentication failure is an outage in progress, not a warning.** A
 *    credential being refused *now* is already dead — days-remaining is
 *    meaningless and thresholds do not apply. `authFailed` is reported
 *    separately from `expired` so an alert can page on it immediately, and
 *    separately again from `unreachable`, which is a statement about the
 *    network rather than about the credential.
 *
 *    What counts as refusal is provider-specific, and getting it wrong in
 *    either direction is expensive. GitLab answers a dead token with `401` but
 *    answers a *working* token that merely lacks the scope to introspect
 *    itself with `403 insufficient_scope`; reading that as `authFailed` would
 *    page somebody over a credential that is doing its job. Each probe decides
 *    for its own provider rather than sharing one rule.
 *
 * 4. **Read-only, by construction.** Every probe here is a decode or a GET.
 *    There is no method that can create, rotate or revoke anything, which is
 *    what makes it safe to run unattended on a schedule against production
 *    credentials. Rotation deliberately lives elsewhere — see
 *    `@sntxrr/gitlab-token` for the GitLab lifecycle side.
 *
 * @module
 */
// extensions/models/credential_expiry.ts
import { z } from "npm:zod@4";

/** How a credential's expiry can be discovered. */
export const PROBE_KINDS = [
  "jwt",
  "github-pat",
  "gitlab-pat",
  "pve-token",
] as const;
/** One of the supported probe kinds, narrowed from {@link PROBE_KINDS}. */
export type ProbeKind = typeof PROBE_KINDS[number];

/**
 * Outcomes, ordered worst-first. `authFailed` outranks `expired` because a
 * credential that is refused *now* is an outage, whereas one that lapsed at
 * some point may already have been replaced everywhere that matters.
 */
export const STATUSES = [
  "authFailed",
  "expired",
  "critical",
  "warn",
  "noExpiry",
  "unreachable",
  "ok",
] as const;
/** One of the reportable outcomes, narrowed from {@link STATUSES}. */
export type Status = typeof STATUSES[number];

const CredentialInputSchema = z.object({
  id: z.string().min(1).describe(
    "Stable identifier, matching the manifest entry this credential corresponds to, e.g. connect-token/deploy-bot",
  ),
  kind: z.enum(PROBE_KINDS).describe(
    "How to read this credential's expiry. `jwt` decodes the exp claim; " +
      "`github-pat` reads GitHub's token-expiration response header; " +
      "`gitlab-pat` reads expires_at from GitLab's token self-introspection endpoint; " +
      "`pve-token` reads the Proxmox VE user record, which embeds each token's expire.",
  ),
  secret: z.string().min(1).meta({ sensitive: true }).describe(
    "The credential itself. Supply via vault.get() — never inline. This is the same value the consuming job uses, deliberately: see module docs.",
  ),
  note: z.string().default("").describe(
    "Free text carried onto the resource, e.g. which job would break. Shown in alerts.",
  ),
  subject: z.string().default("").describe(
    "`pve-token` only: the token to REPORT ON, as `user@realm!tokenid`, when it is not the " +
      "one authenticating. Leave unset to have the credential report on itself. This exists " +
      "because a least-privilege Proxmox token has no Sys.Audit and so cannot read its own " +
      "expiry -- granting it that to make it self-monitoring would widen the blast radius " +
      "the scoping was for. A separate read-only credential reads on its behalf instead.",
  ),
});

const GlobalArgsSchema = z.object({
  credentials: z.array(CredentialInputSchema).min(1).describe(
    "The credentials to probe.",
  ),
  warnDays: z.array(z.number().int().positive()).default([30, 14, 7]).describe(
    "Day thresholds at which a credential is reported `warn`. The largest is the point at which it first becomes visible.",
  ),
  criticalDays: z.number().int().positive().default(3).describe(
    "At or below this many days remaining, status becomes `critical` rather than `warn`.",
  ),
  apiBaseUrl: z.string().url().default("https://api.github.com").describe(
    "GitHub API base URL, for `github-pat` probes. Override for GitHub Enterprise Server.",
  ),
  gitlabBaseUrl: z.string().url().default("https://gitlab.com").describe(
    "GitLab instance base URL, for `gitlab-pat` probes, without the /api/v4 suffix. Override for self-managed.",
  ),
  pveBaseUrl: z.string().url().default("https://pve.example.invalid").describe(
    "Proxmox VE base URL, for `pve-token` probes, without the /api2/json suffix. " +
      "There is no sensible default -- the placeholder is deliberately unroutable so a " +
      "missing override fails as `unreachable` rather than silently probing somewhere real. " +
      "Point it at a reverse proxy holding a publicly-trusted certificate: a PVE node's own " +
      "cluster CA omits the keyUsage extension, which OpenSSL 3 and rustls both reject, so " +
      "hitting port 8006 directly cannot be made to validate.",
  ),
  timeoutMs: z.number().int().positive().default(15000).describe(
    "Abort any single probe request after this long.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const CredentialSchema = z.object({
  id: z.string(),
  kind: z.enum(PROBE_KINDS),
  status: z.enum(STATUSES),
  expiresAt: z.string().nullable(),
  daysRemaining: z.number().nullable(),
  note: z.string(),
  detail: z.string(),
  checkedAt: z.string(),
});

const AuditSchema = z.object({
  checkedAt: z.string(),
  total: z.number(),
  ok: z.number(),
  warn: z.number(),
  critical: z.number(),
  expired: z.number(),
  authFailed: z.number(),
  unreachable: z.number(),
  noExpiry: z.number(),
  /** Worst (smallest) daysRemaining across everything that HAS an expiry. */
  soonestDays: z.number().nullable(),
  soonestId: z.string().nullable(),
  /**
   * True when anything needs a human. Deliberately excludes `noExpiry`: that is
   * a standing design debt to be tracked, not a nightly page.
   */
  actionable: z.boolean(),
  /**
   * True when today is a day worth interrupting someone. `actionable` alone is
   * the wrong gate for a daily run: a credential 29 days out is actionable for
   * 29 consecutive days, and an alert that repeats an unchanged fact daily for a
   * month is one that gets filtered. This fires on the day a threshold is
   * CROSSED, then every day once inside `criticalDays`, and immediately for any
   * outage-shaped status.
   */
  notifyToday: z.boolean(),
  /** Why `notifyToday` is set, for the notification subject line. */
  notifyReason: z.string(),
  /** One line per non-ok credential, ready to drop into a notification body. */
  summary: z.string(),
});

/**
 * The subset of swamp's structured logger this model uses. Declared locally
 * rather than imported so the module stays dependency-free apart from zod.
 */
export type Logger = {
  info: (msg: string, fields?: Record<string, unknown>) => void;
  warn: (msg: string, fields?: Record<string, unknown>) => void;
};

/** Decode a JWT payload without verifying it. Verification is the server's job. */
export function decodeJwtExp(token: string): number | null | "malformed" {
  const parts = token.trim().split(".");
  if (parts.length !== 3 || !parts[1]) return "malformed";
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const claims = JSON.parse(atob(padded)) as Record<string, unknown>;
    const exp = claims["exp"];
    if (exp === undefined || exp === null) return null;
    if (typeof exp !== "number") return "malformed";
    return exp;
  } catch {
    return "malformed";
  }
}

/**
 * GitHub reports a PAT's expiry in a response header rather than a body field,
 * which is why this looks like a HEAD-ish probe rather than an API call for
 * data. A fine-grained or classic token with no expiry simply omits the header.
 */
export function parseGithubExpiryHeader(value: string | null): number | null {
  if (!value) return null;
  // Format: "2026-11-11 23:58:42 UTC"
  const cleaned = value.trim().replace(/\s+UTC$/i, "Z").replace(" ", "T");
  const ms = Date.parse(cleaned);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/**
 * GitLab reports expiry as a bare `YYYY-MM-DD` date, not a timestamp, so the
 * moment of death has to be chosen rather than read.
 *
 * It is anchored to UTC midnight at the *start* of that date — the earliest
 * instant the token could stop working. Choosing the end of the day instead
 * would buy a day of apparent headroom that may not exist, and an expiry
 * monitor that is optimistic by a day is one that reports safe on the morning
 * something has already broken.
 */
export function parseGitlabExpiryDate(value: unknown): number | null {
  if (typeof value !== "string" || value.trim() === "") return null;
  const ms = Date.parse(`${value.trim()}T00:00:00Z`);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/**
 * Resource instance names are derived from the credential id, but ids are
 * manifest-shaped (`connect-token/deploy-bot`) and a `/` in a storage key is a
 * hazard in every system that has ever had one. The sibling sweep model in this
 * fleet quietly avoids the same thing by writing bare repo names rather than
 * `owner/repo`; this makes the reason explicit instead.
 *
 * The raw id is still written into the resource body, so nothing is lost -- only
 * the key is normalised.
 */
export function resourceNameFor(id: string): string {
  return id.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
}

/**
 * Fail before probing anything, not halfway through.
 *
 * Two ids that differ but normalise to the same instance name would have the
 * second silently overwrite the first -- one credential would vanish from the
 * audit while the run still reported success, which is precisely the silent
 * under-count this model exists to prevent elsewhere.
 */
export function preflight(
  credentials: Array<{ id: string }>,
): string[] {
  const problems: string[] = [];
  const seenId = new Set<string>();
  const byName = new Map<string, string>();
  for (const c of credentials) {
    if (seenId.has(c.id)) problems.push(`duplicate id: ${c.id}`);
    seenId.add(c.id);
    const name = resourceNameFor(c.id);
    if (!name) {
      problems.push(`id has no usable characters for a resource name: ${c.id}`);
      continue;
    }
    const clash = byName.get(name);
    if (clash && clash !== c.id) {
      problems.push(
        `ids "${clash}" and "${c.id}" both normalise to resource name "${name}"`,
      );
    }
    byName.set(name, c.id);
  }
  return problems;
}

/**
 * Should today's run interrupt anyone?
 *
 * Anything outage-shaped always does. Otherwise it fires on the exact day a
 * warn threshold is crossed, and every day once inside `criticalDays` -- so a
 * 90-day credential produces four notifications in its life rather than thirty.
 */
export function shouldNotify(
  results: Array<{ status: Status; daysRemaining: number | null }>,
  policy: { warnDays: number[]; criticalDays: number },
): { notify: boolean; reason: string } {
  const urgent = results.filter((r) =>
    r.status === "authFailed" || r.status === "expired" ||
    r.status === "unreachable"
  );
  if (urgent.length > 0) {
    return { notify: true, reason: urgent[0].status };
  }
  const critical = results.filter((r) =>
    r.daysRemaining !== null && r.daysRemaining <= policy.criticalDays
  );
  if (critical.length > 0) return { notify: true, reason: "critical" };

  const crossing = results.some((r) =>
    r.daysRemaining !== null && policy.warnDays.includes(r.daysRemaining)
  );
  return crossing
    ? { notify: true, reason: "threshold" }
    : { notify: false, reason: "" };
}

/** Map days-remaining onto a status, given the configured thresholds. */
export function classify(
  daysRemaining: number | null,
  policy: { warnDays: number[]; criticalDays: number },
): Status {
  if (daysRemaining === null) return "noExpiry";
  if (daysRemaining < 0) return "expired";
  if (daysRemaining <= policy.criticalDays) return "critical";
  const widest = Math.max(...policy.warnDays);
  return daysRemaining <= widest ? "warn" : "ok";
}

type ProbeResult = {
  status: Status;
  expiresAt: string | null;
  daysRemaining: number | null;
  detail: string;
};

const DAY_MS = 86_400_000;

function fromEpoch(
  exp: number,
  now: Date,
  policy: { warnDays: number[]; criticalDays: number },
): ProbeResult {
  const expiresAt = new Date(exp * 1000);
  // Floor, not round: 0.9 days left must read as 0, never as 1. Rounding up
  // here would let a credential expire on a day the report called safe.
  const daysRemaining = Math.floor(
    (expiresAt.getTime() - now.getTime()) / DAY_MS,
  );
  return {
    status: classify(daysRemaining, policy),
    expiresAt: expiresAt.toISOString(),
    daysRemaining,
    detail: "",
  };
}

// Not async: decoding a JWT is local arithmetic, no I/O. Keeping it sync makes
// that visible at the call site -- this probe cannot hang, time out, or be
// affected by the network, unlike every other probe here.
function probeJwt(
  secret: string,
  now: Date,
  policy: { warnDays: number[]; criticalDays: number },
): ProbeResult {
  const exp = decodeJwtExp(secret);
  if (exp === "malformed") {
    // Not "unreachable": nothing was contacted. A value that does not parse as
    // a JWT is a configuration fault, and silently treating it as no-expiry
    // would report a broken probe as a healthy credential.
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: "value is not a well-formed JWT",
    };
  }
  if (exp === null) {
    return {
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail: "no exp claim — unmonitorable by any clock",
    };
  }
  return fromEpoch(exp, now, policy);
}

async function probeGithubPat(
  secret: string,
  globalArgs: GlobalArgs,
  now: Date,
): Promise<ProbeResult> {
  const url = `${globalArgs.apiBaseUrl.replace(/\/+$/, "")}/user`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: {
        "Authorization": `Bearer ${secret}`,
        "Accept": "application/vnd.github+json",
      },
      signal: AbortSignal.timeout(globalArgs.timeoutMs),
    });
  } catch (cause) {
    // The network failed, which says nothing about the credential. Reported
    // distinctly so an alert does not cry "expired" over a DNS blip.
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `request failed: ${String(cause)}`,
    };
  }

  if (res.status === 401 || res.status === 403) {
    // Already an outage. Thresholds are meaningless for a credential being
    // refused right now.
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: `GitHub refused the token (HTTP ${res.status})`,
    };
  }
  if (!res.ok) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `unexpected HTTP ${res.status}`,
    };
  }

  const exp = parseGithubExpiryHeader(
    res.headers.get("github-authentication-token-expiration"),
  );
  if (exp === null) {
    return {
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail: "token authenticates but reports no expiration header",
    };
  }
  return fromEpoch(exp, now, globalArgs);
}

/**
 * GitLab has no expiry header; a token's own record is read back through
 * `/personal_access_tokens/self`, which works for project and group access
 * tokens too — GitLab implements both as personal tokens belonging to a bot
 * user.
 *
 * The reason this probe is longer than the GitHub one is the 403. GitLab
 * answers an invalid, revoked or expired token with `401`, but answers a
 * perfectly good token that merely lacks the scope to introspect itself with
 * `403 insufficient_scope`. Collapsing those two into `authFailed` would page
 * somebody at 3am over a `read_registry` token that is working exactly as
 * intended. The 403 is reported as `noExpiry` instead — the credential is
 * *unmonitorable*, which is this model's existing name for that, and it is a
 * fixable configuration fact that belongs in a review rather than a nightly
 * alert.
 */
async function probeGitlabPat(
  secret: string,
  globalArgs: GlobalArgs,
  now: Date,
): Promise<ProbeResult> {
  const base = globalArgs.gitlabBaseUrl.replace(/\/+$/, "");
  const url = `${base}/api/v4/personal_access_tokens/self`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: {
        "PRIVATE-TOKEN": secret,
        "Accept": "application/json",
      },
      signal: AbortSignal.timeout(globalArgs.timeoutMs),
    });
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `request failed: ${String(cause)}`,
    };
  }

  if (res.status === 401) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail:
        "GitLab refused the token (HTTP 401 — invalid, revoked or expired)",
    };
  }
  if (res.status === 403) {
    // Authenticated fine; just not allowed to look at itself.
    return {
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail:
        "token authenticates but lacks the api/read_api scope to read its own " +
        "expiry (HTTP 403) — unmonitorable until the scope is widened",
    };
  }
  if (!res.ok) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `unexpected HTTP ${res.status}`,
    };
  }

  let body: Record<string, unknown>;
  try {
    body = await res.json() as Record<string, unknown>;
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `could not parse GitLab's response: ${String(cause)}`,
    };
  }

  // A revoked token normally 401s, but an instance can serve the record back
  // with revoked set. Trusting expires_at alone would then report a dead
  // credential as healthy for as long as its nominal expiry is in the future.
  if (body.revoked === true || body.active === false) {
    return {
      status: "authFailed",
      expiresAt: typeof body.expires_at === "string" ? body.expires_at : null,
      daysRemaining: null,
      detail: "GitLab reports the token as revoked or inactive",
    };
  }

  const exp = parseGitlabExpiryDate(body.expires_at);
  if (exp === null) {
    return {
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail: "token reports no expires_at — unmonitorable by any clock",
    };
  }
  return fromEpoch(exp, now, globalArgs);
}

/** A probe, normalised to one signature so the dispatch can be exhaustive. */
type Probe = (
  secret: string,
  globalArgs: GlobalArgs,
  now: Date,
  subject?: string,
) => ProbeResult | Promise<ProbeResult>;

/**
 * Parse a Proxmox API token into the two identifiers the API needs.
 *
 * The wire format is `user@realm!tokenid=<uuid>`. Only the part after `=` is
 * secret; the rest is an address, which is why this returns it for use in a URL
 * and in a detail string without redacting anything.
 *
 * Exported for tests.
 */
export function parsePveToken(
  secret: string,
): { userid: string; tokenid: string } | null {
  const bang = secret.indexOf("!");
  const eq = secret.indexOf("=", bang + 1);
  if (bang <= 0 || eq <= bang + 1) return null;
  const userid = secret.slice(0, bang);
  const tokenid = secret.slice(bang + 1, eq);
  if (!userid.includes("@") || tokenid.length === 0) return null;
  return { userid, tokenid };
}

/**
 * Parse a `user@realm!tokenid` subject -- the same shape as a token's value with
 * the secret half absent, because a subject names a token rather than proving
 * anything about it.
 *
 * Exported for tests.
 */
export function parsePveSubject(
  subject: string,
): { userid: string; tokenid: string } | null {
  const bang = subject.indexOf("!");
  if (bang <= 0 || bang === subject.length - 1) return null;
  const userid = subject.slice(0, bang);
  const tokenid = subject.slice(bang + 1);
  // A subject carrying an '=' is a SECRET pasted where an identifier belongs.
  // Reject it rather than silently storing it in a resource attribute.
  if (!userid.includes("@") || tokenid.includes("=")) return null;
  return { userid, tokenid };
}

/**
 * Proxmox keeps a token's expiry server-side -- there is nothing to decode out
 * of the value itself -- so this reads it back from the API.
 *
 * It reads `GET /access/users/{userid}`, NOT
 * `GET /access/users/{userid}/token/{tokenid}`. The dedicated token endpoint
 * needs `User.Modify`, which is permission to *create and delete* this user's
 * tokens and is far too much to hand a monitor. The user record answers with a
 * `tokens` map that embeds each token's `expire` and is readable with nothing
 * but `Sys.Audit` -- so a `PVEAuditor` token can report on itself, and on every
 * other token in the cluster, while remaining unable to change anything.
 *
 * `expire: 0` means never. That is Proxmox's encoding, not a missing field, and
 * it maps to `noExpiry` rather than to an epoch in 1970.
 *
 * A 403 is reported as `noExpiry`, not `authFailed`, for the same reason the
 * GitLab probe does: the credential works, it simply lacks `Sys.Audit` and so is
 * *unmonitorable*. That is a configuration fact for a review, not an outage to
 * wake somebody for. Only 401 means the token was refused.
 */
async function probePveToken(
  secret: string,
  globalArgs: GlobalArgs,
  now: Date,
  subject?: string,
): Promise<ProbeResult> {
  // The authenticating token must always parse -- that is what goes in the header.
  if (parsePveToken(secret) === null) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: "secret is not in Proxmox `user@realm!tokenid=<secret>` form",
    };
  }
  // When one credential reads on another's behalf, say so on every result.
  // Without it a reader cannot tell whether a reported expiry belongs to the
  // credential named by `id` or to the one that authenticated -- and those
  // differ precisely when the entry matters most.
  const onBehalfOf = (r: ProbeResult): ProbeResult =>
    subject && subject.length > 0
      ? {
        ...r,
        detail:
          `${r.detail} (read by the probe credential on behalf of ${subject})`,
      }
      : r;

  // What we REPORT ON is the subject when given, otherwise the token itself.
  // Deriving it from the secret by default keeps the simple case simple; naming
  // a subject is what lets one read-only credential cover a whole cluster.
  const parsed = subject && subject.length > 0
    ? parsePveSubject(subject)
    : parsePveToken(secret);
  if (parsed === null) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: "`subject` is not in Proxmox `user@realm!tokenid` form",
    };
  }
  const base = globalArgs.pveBaseUrl.replace(/\/+$/, "");
  const url = `${base}/api2/json/access/users/${
    encodeURIComponent(parsed.userid)
  }`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { "Authorization": `PVEAPIToken=${secret}` },
      signal: AbortSignal.timeout(globalArgs.timeoutMs),
    });
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `request failed: ${String(cause)}`,
    };
  }

  if (res.status === 401) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: "Proxmox refused the token (HTTP 401)",
    };
  }
  if (res.status === 403) {
    return {
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail:
        `token authenticates but cannot read /access/users/${parsed.userid} ` +
        "(HTTP 403) -- it needs Sys.Audit to report its own expiry",
    };
  }
  if (!res.ok) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `unexpected HTTP ${res.status}`,
    };
  }

  let body: unknown;
  try {
    body = await res.json();
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `response was not JSON: ${String(cause)}`,
    };
  }

  const tokens = (body as { data?: { tokens?: Record<string, unknown> } })
    ?.data?.tokens;
  const entry = tokens?.[parsed.tokenid] as { expire?: unknown } | undefined;
  if (entry === undefined) {
    // The user exists and answered, but this tokenid is not among its tokens.
    // That is a deleted or renamed token being read from a stale config -- an
    // outage in waiting, and emphatically not "no expiry".
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: `no token '${parsed.tokenid}' on user ${parsed.userid} -- ` +
        "deleted, renamed, or the manifest is stale",
    };
  }

  const expire = entry.expire;
  if (typeof expire !== "number" || expire === 0) {
    return onBehalfOf({
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail: "token is configured to never expire",
    });
  }
  return onBehalfOf(fromEpoch(expire, now, globalArgs));
}

/**
 * Resolve a probe kind to its implementation.
 *
 * The `never` assignment is the point of this function: adding an entry to
 * `PROBE_KINDS` without a probe behind it fails the type-check here, rather
 * than falling through to whichever branch a ternary chain happened to end on
 * and reporting one credential type's expiry using another's rules.
 */
export function probeFor(kind: ProbeKind): Probe {
  switch (kind) {
    case "jwt":
      // Wrapped, not referenced directly: decoding a JWT is local arithmetic
      // and takes no globalArgs beyond the thresholds.
      return (secret, globalArgs, now) => probeJwt(secret, now, globalArgs);
    case "github-pat":
      return (secret, globalArgs, now) =>
        probeGithubPat(secret, globalArgs, now);
    case "gitlab-pat":
      return (secret, globalArgs, now) =>
        probeGitlabPat(secret, globalArgs, now);
    case "pve-token":
      return (secret, globalArgs, now, subject) =>
        probePveToken(secret, globalArgs, now, subject);
    default: {
      const unreachable: never = kind;
      throw new Error(`no probe implemented for kind: ${String(unreachable)}`);
    }
  }
}

/**
 * The credential-expiry model: a single read-only `audit` method that probes
 * every configured credential, writes one `credential` resource each plus an
 * `audit` summary, and refuses the whole run rather than report a partial one.
 */
export const model = {
  type: "@sntxrr/credential-expiry",
  description:
    "Probe the credentials a fleet actually holds and report how long each has left, distinguishing expiry from an outage in progress",
  version: "2026.09.08.2",
  // Purely additive: a fourth probe kind and the `pveBaseUrl` global argument
  // that serves it. No stored attribute changes shape, so the migration is a
  // no-op -- but it has to be DECLARED, or existing instances pin themselves to
  // the version they were created at and quietly never see the new probe.
  //
  // `pveBaseUrl` carries a default, so a model that does not set it still
  // validates. The default is deliberately unroutable rather than a real host,
  // so an unset override fails as `unreachable` instead of probing somewhere
  // it was never pointed at.
  upgrades: [
    {
      toVersion: "2026.09.08.1",
      description:
        "Adds the `pve-token` probe kind and the `pveBaseUrl` global argument. Nothing to migrate: the credential and audit resource schemas are unchanged, and existing `jwt`, `github-pat` and `gitlab-pat` entries keep their behaviour exactly. To monitor a Proxmox token, add an entry with `kind: pve-token` whose secret is the full `user@realm!tokenid=<secret>` string, and set `pveBaseUrl` to a reverse proxy holding a publicly-trusted certificate -- a PVE cluster CA omits keyUsage, which OpenSSL 3 and rustls both reject, so port 8006 direct cannot validate.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.09.08.2",
      description:
        "Adds the optional `subject` field, so a `pve-token` entry can report on a token OTHER than the one it authenticates with. Nothing to migrate -- `subject` defaults to empty, and an empty subject keeps the previous behaviour of deriving the reported token from the secret. Set it when a least-privilege token cannot read its own expiry: the entry's `secret` becomes a read-only credential holding Sys.Audit, and `subject` names the token being watched.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgsSchema,
  resources: {
    "credential": {
      description:
        "One probed credential: its expiry, days remaining, and status",
      schema: CredentialSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
    "audit": {
      description:
        "Summary of one audit pass: counts by status, the soonest expiry, and whether anything needs a human",
      schema: AuditSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
  },
  methods: {
    audit: {
      description:
        "Probe every configured credential and write one resource each, plus a summary",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: {
          globalArgs: GlobalArgs;
          logger: Logger;
          writeResource: (
            specName: string,
            name: string,
            data: Record<string, unknown>,
          ) => Promise<{ name: string }>;
        },
      ) => {
        const { globalArgs, logger } = context;

        const problems = preflight(globalArgs.credentials);
        if (problems.length > 0) {
          // Refuse the whole run. A partial audit that still reports success is
          // worse than no audit -- it is the shape of every silent under-count.
          throw new Error(
            `credential-expiry configuration is invalid:\n  ${
              problems.join("\n  ")
            }`,
          );
        }

        const now = new Date();
        const checkedAt = now.toISOString();
        const handles: Array<{ name: string }> = [];
        const counts: Record<Status, number> = {
          authFailed: 0,
          expired: 0,
          critical: 0,
          warn: 0,
          noExpiry: 0,
          unreachable: 0,
          ok: 0,
        };
        const lines: string[] = [];
        const outcomes: Array<
          { status: Status; daysRemaining: number | null }
        > = [];
        let soonestDays: number | null = null;
        let soonestId: string | null = null;

        for (const cred of globalArgs.credentials) {
          // A switch rather than a ternary chain: the compiler now fails the
          // build if a probe kind is added to PROBE_KINDS without a probe
          // behind it, instead of quietly routing it to whichever branch
          // happened to be last.
          const result = await probeFor(cred.kind)(
            cred.secret,
            globalArgs,
            now,
            cred.subject,
          );

          counts[result.status] += 1;
          outcomes.push({
            status: result.status,
            daysRemaining: result.daysRemaining,
          });

          if (
            result.daysRemaining !== null &&
            (soonestDays === null || result.daysRemaining < soonestDays)
          ) {
            soonestDays = result.daysRemaining;
            soonestId = cred.id;
          }

          if (result.status !== "ok") {
            const when = result.daysRemaining !== null
              ? `${result.daysRemaining}d left`
              : result.detail;
            lines.push(
              `${result.status.toUpperCase()} ${cred.id} — ${when}${
                cred.note ? ` (${cred.note})` : ""
              }`,
            );
          }

          // The secret is never logged, and never written to a resource. Only
          // its id, its expiry and its status leave this method.
          logger.info("{id}: {status}", {
            id: cred.id,
            status: result.status,
          });

          handles.push(
            await context.writeResource(
              "credential",
              resourceNameFor(cred.id),
              {
                id: cred.id,
                kind: cred.kind,
                status: result.status,
                expiresAt: result.expiresAt,
                daysRemaining: result.daysRemaining,
                note: cred.note,
                detail: result.detail,
                checkedAt,
              },
            ),
          );
        }

        // `noExpiry` is deliberately NOT actionable. It is a standing design
        // debt that belongs in a review, not a nightly page — and a page that
        // fires every night over an unchanged fact is one that gets muted.
        const actionable =
          counts.authFailed + counts.expired + counts.critical +
              counts.warn + counts.unreachable > 0;

        logger.info(
          "{total} credentials probed; {actionable}",
          {
            total: globalArgs.credentials.length,
            actionable: actionable ? "action needed" : "all clear",
          },
        );

        const { notify, reason } = shouldNotify(outcomes, globalArgs);

        handles.push(
          await context.writeResource("audit", "current", {
            checkedAt,
            total: globalArgs.credentials.length,
            ...counts,
            soonestDays,
            soonestId,
            actionable,
            notifyToday: notify,
            notifyReason: reason,
            summary: lines.join("\n"),
          }),
        );

        return { dataHandles: handles };
      },
    },
  },
};
