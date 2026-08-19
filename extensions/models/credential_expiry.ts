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
 * 3. **An authentication failure is an outage in progress, not a warning.** If
 *    a probe gets 401/403, the credential is already dead — days-remaining is
 *    meaningless and thresholds do not apply. `authFailed` is reported
 *    separately from `expired` so an alert can page on it immediately, and
 *    separately again from `unreachable`, which is a statement about the
 *    network rather than about the credential.
 *
 * 4. **Read-only, by construction.** Every probe here is a decode or a GET.
 *    There is no method that can create, rotate or revoke anything, which is
 *    what makes it safe to run unattended on a schedule against production
 *    credentials.
 *
 * @module
 */
// extensions/models/credential_expiry.ts
import { z } from "npm:zod@4";

/** How a credential's expiry can be discovered. */
export const PROBE_KINDS = ["jwt", "github-pat"] as const;
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
export type Status = typeof STATUSES[number];

const CredentialInputSchema = z.object({
  id: z.string().min(1).describe(
    "Stable identifier, matching the manifest entry this credential corresponds to, e.g. connect-token/deploy-bot",
  ),
  kind: z.enum(PROBE_KINDS).describe(
    "How to read this credential's expiry. `jwt` decodes the exp claim; `github-pat` reads GitHub's token-expiration response header.",
  ),
  secret: z.string().min(1).meta({ sensitive: true }).describe(
    "The credential itself. Supply via vault.get() — never inline. This is the same value the consuming job uses, deliberately: see module docs.",
  ),
  note: z.string().default("").describe(
    "Free text carried onto the resource, e.g. which job would break. Shown in alerts.",
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

export const model = {
  type: "@sntxrr/credential-expiry",
  description:
    "Probe the credentials a fleet actually holds and report how long each has left, distinguishing expiry from an outage in progress",
  version: "2026.08.19.2",
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
          const result = cred.kind === "jwt"
            ? probeJwt(cred.secret, now, globalArgs)
            : await probeGithubPat(cred.secret, globalArgs, now);

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
