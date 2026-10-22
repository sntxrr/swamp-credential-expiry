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
 * 4. **One unreadable secret is one finding, not a dead audit.** An entry can
 *    name its secret as a vault reference (`secretRef`) instead of an inline
 *    `vault.get()`. Inline expressions are resolved before the method runs, so
 *    a single missing vault item kills the step and every other credential
 *    goes unchecked with it. A `secretRef` is resolved here, per entry, and a
 *    failure is reported as that entry's `unresolved` status -- the others are
 *    still probed.
 *
 * 5. **Read-only, by construction.** Every probe here is a decode, a GET, or
 *    (for `swamp-serve-token`) a `swamp access token list`, which reads token
 *    metadata and never a token's secret. The `sweep` method is a paginated GET
 *    of a Scaleway organization's key listing.
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
  "b2-key",
  "scaleway-key",
  "swamp-serve-token",
] as const;
/** One of the supported probe kinds, narrowed from {@link PROBE_KINDS}. */
export type ProbeKind = typeof PROBE_KINDS[number];

/**
 * Kinds whose expiry is read from a record the model can already see, so the
 * entry holds no secret at all. Giving one a `secret` would only put a value
 * somewhere it is never used.
 */
export const SECRETLESS_KINDS: ReadonlySet<ProbeKind> = new Set([
  "swamp-serve-token",
]);

/**
 * Outcomes, ordered worst-first. `authFailed` outranks `expired` because a
 * credential that is refused *now* is an outage, whereas one that lapsed at
 * some point may already have been replaced everywhere that matters.
 * `unresolved` sits next to it: the monitor could not read the secret, so the
 * credential's state is unknown, and unknown is not a pass.
 */
export const STATUSES = [
  "authFailed",
  "unresolved",
  "expired",
  "critical",
  "warn",
  "noExpiry",
  "unreachable",
  "ok",
] as const;
/** One of the reportable outcomes, narrowed from {@link STATUSES}. */
export type Status = typeof STATUSES[number];

const SecretRefSchema = z.object({
  vault: z.string().min(1).describe(
    "Name of the swamp vault holding the secret.",
  ),
  key: z.string().min(1).describe(
    "Key within that vault, exactly as vault.get() would take it, e.g. item/field.",
  ),
});

const CredentialInputSchema = z.object({
  id: z.string().min(1).describe(
    "Stable identifier, matching the manifest entry this credential corresponds to, e.g. connect-token/deploy-bot",
  ),
  kind: z.enum(PROBE_KINDS).describe(
    "How to read this credential's expiry. `jwt` decodes the exp claim; " +
      "`github-pat` reads GitHub's token-expiration response header; " +
      "`gitlab-pat` reads expires_at from GitLab's token self-introspection endpoint; " +
      "`pve-token` reads the Proxmox VE user record, which embeds each token's expire; " +
      "`b2-key` reads Backblaze B2's key listing, which embeds each key's expirationTimestamp; " +
      "`scaleway-key` reads a Scaleway IAM API key record, which carries expires_at; " +
      "`swamp-serve-token` reads expiresAt for the server token named by `subject` from " +
      "`swamp access token list`, and takes no secret.",
  ),
  // `sensitive` is set on BOTH sides of `.optional()`: each wrapper is its own
  // schema with its own metadata, so a flag set only inside is invisible to
  // anything that reads the field's outer schema.
  secret: z.string().min(1).meta({ sensitive: true }).optional().describe(
    "The credential itself. Supply via vault.get() or env — never inline. This is the same value the consuming job uses, deliberately: see module docs. " +
      "Prefer `secretRef` for vault-held secrets: an inline vault.get() that cannot be resolved fails the whole audit before any credential is probed.",
  ).meta({ sensitive: true }),
  secretRef: SecretRefSchema.optional().describe(
    "Where to read the credential from, resolved by the method itself, per entry. " +
      "A secret that cannot be read is reported as this entry's `unresolved` status " +
      "instead of failing the run. Set exactly one of `secret` and `secretRef`.",
  ),
  note: z.string().default("").describe(
    "Free text carried onto the resource, e.g. which job would break. Shown in alerts.",
  ),
  subject: z.string().default("").describe(
    "The credential to REPORT ON when it is not the one authenticating: for `pve-token` a " +
      "`user@realm!tokenid`, for `b2-key` an applicationKeyId, for `scaleway-key` an access " +
      "key id (`SCW` + 17 characters), for `swamp-serve-token` the server token's name. " +
      "Leave unset to have a `pve-token` or `b2-key` report " +
      "on itself; `scaleway-key` and `swamp-serve-token` REQUIRE it, because a Scaleway secret key does not reveal " +
      "which access key it belongs to. This exists because a least-privilege credential " +
      "often cannot read its own expiry -- granting it that to make it self-monitoring would " +
      "widen the blast radius the scoping was for. A separate read-only credential reads on " +
      "its behalf instead. Never a secret: subjects are written into resources in clear.",
  ),
}).superRefine((c, ctx) => {
  if (SECRETLESS_KINDS.has(c.kind)) {
    if (c.secret !== undefined || c.secretRef !== undefined) {
      ctx.addIssue({
        code: "custom",
        message:
          `\`${c.kind}\` takes no secret: set neither \`secret\` nor \`secretRef\``,
      });
    }
    return;
  }
  if ((c.secret === undefined) === (c.secretRef === undefined)) {
    ctx.addIssue({
      code: "custom",
      message: "set exactly one of `secret` and `secretRef`",
    });
  }
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
  b2BaseUrl: z.string().url().default("https://api.backblazeb2.com").describe(
    "Backblaze B2 authorization endpoint, for `b2-key` probes, without the /b2api suffix. " +
      "Unlike pveBaseUrl this has a real default: B2's authorization host is universal, and " +
      "the per-account storage API URL is discovered from the authorize response rather than " +
      "configured.",
  ),
  scwBaseUrl: z.string().url().default("https://api.scaleway.com").describe(
    "Scaleway API base URL, for `scaleway-key` probes, without the /iam suffix. IAM is a " +
      "global (region-less) API, so the public default is right for every organization.",
  ),
  scwOrganizationId: z.string().default("").describe(
    "Scaleway organization id (a UUID), for the `sweep` method only. The IAM api-keys " +
      "listing answers 400 without one, so a sweep with this unset reports `misconfigured` " +
      "rather than listing nothing. Not a secret, and unused by `audit`.",
  ),
  swampBin: z.string().min(1).default("swamp").describe(
    "The swamp CLI, for `swamp-serve-token` probes. Run as `swamp access token list --json`.",
  ),
  swampRepoDir: z.string().default("").describe(
    "Repository whose server tokens a `swamp-serve-token` probe reads, passed as --repo-dir. " +
      "Empty uses the method's working directory. Set it to the served repository, so a " +
      "run anywhere else fails as `unreachable` instead of reading some other repo's tokens.",
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
  unresolved: z.number(),
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

/** Outcomes of a plane sweep, worst-first. */
export const SWEEP_STATUSES = [
  "authFailed",
  "unresolved",
  "misconfigured",
  "unreachable",
  "findings",
  "ok",
] as const;
/** One of the sweep outcomes, narrowed from {@link SWEEP_STATUSES}. */
export type SweepStatus = typeof SWEEP_STATUSES[number];

const SweepKeySchema = z.object({
  // An access key id is an identifier, not a secret: Scaleway prints it in its
  // console and audit trail, and the secret half is never read or stored.
  // swamp-quality-ignore credentials-sensitive-field
  accessKey: z.string(),
  bearerType: z.enum(["application", "user", "unknown"]),
  bearerId: z.string().nullable(),
  description: z.string(),
  createdAt: z.string().nullable(),
  expiresAt: z.string().nullable(),
  manifested: z.boolean(),
});

const SweepSchema = z.object({
  checkedAt: z.string(),
  plane: z.literal("scaleway"),
  status: z.enum(SWEEP_STATUSES),
  /** Why the sweep could not list the plane; empty when it could. */
  detail: z.string(),
  /** The `scaleway-key` entry whose secret listed the organization. */
  credentialId: z.string().nullable(),
  /** Keys the organization holds; null when the listing failed. */
  total: z.number().nullable(),
  /** Distinct access key ids named by `scaleway-key` entries. */
  manifested: z.number(),
  /** Keys in the organization that no `scaleway-key` entry names. */
  unmanifested: z.array(z.string()),
  /** Keys in the organization with no expiry, manifested or not. */
  noExpiry: z.array(z.string()),
  keys: z.array(SweepKeySchema),
  /** True when the sweep found something or could not run: see the method. */
  notify: z.boolean(),
  notifyReason: z.string(),
  /** One line per finding, ready to drop into a notification body. */
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

/** Instance name of the audit summary; no credential may normalise to it. */
export const AUDIT_INSTANCE = "current";

/**
 * Instance name of the Scaleway plane sweep. Reserved like
 * {@link AUDIT_INSTANCE}: `data.latest()` addresses an instance by name alone,
 * so a credential normalising to it would be read in place of the sweep.
 */
export const SWEEP_INSTANCE = "sweep-scaleway";

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
    if (name === AUDIT_INSTANCE || name === SWEEP_INSTANCE) {
      // The summary is written under this name; a credential written there too
      // would be overwritten by it, and data.latest() would return the wrong shape.
      problems.push(
        `id "${c.id}" normalises to "${name}", which the ${
          name === AUDIT_INSTANCE ? "audit summary" : "Scaleway sweep"
        } uses`,
      );
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
    r.status === "authFailed" || r.status === "unresolved" ||
    r.status === "expired" || r.status === "unreachable"
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

/** The part of swamp's vault service this model uses. */
export type VaultLike = {
  get: (vaultName: string, key: string) => Promise<string>;
};

/** Longest vault error carried into a resource and an alert body. */
const MAX_UNRESOLVED_DETAIL = 300;

/**
 * Get one entry's secret, or say why it could not be read.
 *
 * Never throws: a failure here is the entry's finding, not the run's. The
 * returned detail names the vault and key -- addresses, not values -- plus the
 * vault's own error, which describes a lookup and holds no secret material.
 * A resolved value is registered with the redactor before anything else can
 * log it.
 */
export async function resolveSecret(
  cred: { secret?: string; secretRef?: { vault: string; key: string } },
  vault: VaultLike | undefined,
  redactor?: { addSecret: (value: string) => void },
): Promise<{ secret: string } | { detail: string }> {
  if (cred.secret !== undefined) return { secret: cred.secret };
  const ref = cred.secretRef;
  if (!ref) return { detail: "entry has neither secret nor secretRef" };
  const where = `${ref.vault}/${ref.key}`;
  if (!vault) {
    return { detail: `no vault service available to read ${where}` };
  }
  let value: string;
  try {
    value = await vault.get(ref.vault, ref.key);
  } catch (e) {
    const msg = (e instanceof Error ? e.message : String(e)).replace(
      /\s+/g,
      " ",
    )
      .trim();
    const detail = `could not read ${where}: ${msg}`;
    return {
      detail: detail.length > MAX_UNRESOLVED_DETAIL
        ? `${detail.slice(0, MAX_UNRESOLVED_DETAIL - 1)}…`
        : detail,
    };
  }
  if (typeof value !== "string" || value === "") {
    // An empty read is a failure, never a pass: 1Password has answered an
    // empty value with exit 0 before.
    return { detail: `${where} resolved to an empty value` };
  }
  redactor?.addSecret(value);
  return { secret: value };
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

  // Everything this probe reads is in the headers. Release the body on every
  // path, or each probe leaves a connection open until garbage collection.
  await res.body?.cancel();

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

  // Only a 2xx body is read; release any other, or the connection stays open.
  if (!res.ok) await res.body?.cancel();

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

/**
 * What a probe may share across entries within one audit. Only the serve token
 * listing today: one `swamp access token list` answers every entry, so the
 * audit reads it once rather than starting the CLI per token.
 */
export type ProbeDeps = {
  serveTokens?: () => Promise<ServeTokenListing>;
};

/** A probe, normalised to one signature so the dispatch can be exhaustive. */
type Probe = (
  secret: string,
  globalArgs: GlobalArgs,
  now: Date,
  subject?: string,
  deps?: ProbeDeps,
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

  // Only a 2xx body is read; release any other, or the connection stays open.
  if (!res.ok) await res.body?.cancel();

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
 * Parse a `<applicationKeyId>:<applicationKey>` secret.
 *
 * That is the same pairing B2 itself takes as HTTP Basic credentials, so the
 * stored value is exactly what the consumer presents -- no re-encoding, and no
 * second field that could drift out of step with the first.
 */
export function parseB2Secret(
  secret: string,
): { keyId: string; appKey: string } | null {
  const colon = secret.indexOf(":");
  if (colon <= 0 || colon === secret.length - 1) return null;
  const keyId = secret.slice(0, colon);
  const appKey = secret.slice(colon + 1);
  // A second colon means the value is not a key pair -- most likely a URL or a
  // config line pasted whole. Refuse rather than probe a truncated id.
  if (appKey.includes(":")) return null;
  return { keyId, appKey };
}

/**
 * Validate a `b2-key` subject: an applicationKeyId, never a key pair.
 *
 * Same discipline as {@link parsePveSubject} -- a subject carrying a `:` is a
 * SECRET pasted where an identifier belongs, and identifiers are written into
 * resource attributes in clear.
 */
export function parseB2Subject(subject: string): string | null {
  if (subject.length === 0 || subject.includes(":")) return null;
  return subject;
}

/**
 * Backblaze keeps a key's expiry server-side, like Proxmox and unlike a JWT, so
 * this reads it back from the API rather than decoding the value.
 *
 * `expirationTimestamp` is in MILLISECONDS, where Proxmox's `expire` is in
 * seconds. Feeding it to {@link fromEpoch} unconverted would report a date in
 * the year 58000 and classify a lapsed key as healthy -- so the conversion is
 * the one thing in this probe worth checking twice.
 *
 * A key can report on itself, but only if it holds `listKeys`. The capability
 * is read from the authorize response rather than inferred from a 401, because
 * B2 answers 401 both for a refused key and for a good key lacking capability,
 * and those are opposite conclusions: an outage versus a monitoring gap.
 */
async function probeB2Key(
  secret: string,
  globalArgs: GlobalArgs,
  now: Date,
  subject?: string,
): Promise<ProbeResult> {
  const parsed = parseB2Secret(secret);
  if (parsed === null) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail:
        "secret is not in Backblaze `<applicationKeyId>:<applicationKey>` form",
    };
  }

  // What we REPORT ON is the subject when given, otherwise the key itself.
  let target = parsed.keyId;
  if (subject !== undefined && subject.length > 0) {
    const parsedSubject = parseB2Subject(subject);
    if (parsedSubject === null) {
      return {
        status: "authFailed",
        expiresAt: null,
        daysRemaining: null,
        detail: "`subject` is not a bare Backblaze applicationKeyId",
      };
    }
    target = parsedSubject;
  }
  const onBehalfOf = (r: ProbeResult): ProbeResult =>
    target !== parsed.keyId
      ? {
        ...r,
        detail:
          `${r.detail} (read by the probe credential on behalf of ${target})`,
      }
      : r;

  const authBase = globalArgs.b2BaseUrl.replace(/\/+$/, "");
  const basic = btoa(`${parsed.keyId}:${parsed.appKey}`);
  let authRes: Response;
  try {
    authRes = await fetch(`${authBase}/b2api/v3/b2_authorize_account`, {
      headers: { "Authorization": `Basic ${basic}` },
      signal: AbortSignal.timeout(globalArgs.timeoutMs),
    });
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `authorize request failed: ${String(cause)}`,
    };
  }
  // Only a 2xx body is read; release any other, or the connection stays open.
  if (!authRes.ok) await authRes.body?.cancel();
  if (authRes.status === 401) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: "Backblaze refused the key (HTTP 401)",
    };
  }
  if (!authRes.ok) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `unexpected HTTP ${authRes.status} from b2_authorize_account`,
    };
  }

  let auth: {
    accountId?: unknown;
    authorizationToken?: unknown;
    apiInfo?: { storageApi?: { apiUrl?: unknown; capabilities?: unknown } };
  };
  try {
    auth = await authRes.json();
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `authorize response was not JSON: ${String(cause)}`,
    };
  }

  const apiUrl = auth.apiInfo?.storageApi?.apiUrl;
  const token = auth.authorizationToken;
  const accountId = auth.accountId;
  if (
    typeof apiUrl !== "string" || typeof token !== "string" ||
    typeof accountId !== "string"
  ) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail:
        "authorize response missing apiUrl, authorizationToken or accountId",
    };
  }

  // Read the capability rather than inferring it from a 401 -- see the doc
  // comment. A key that authenticates but cannot list keys is a monitoring gap,
  // not an outage, and must not page anyone.
  const caps = auth.apiInfo?.storageApi?.capabilities;
  if (!Array.isArray(caps) || !caps.includes("listKeys")) {
    return onBehalfOf({
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail:
        "key authenticates but lacks the listKeys capability, so its expiry cannot be read",
    });
  }

  // startApplicationKeyId begins the listing AT the target, so maxKeyCount=1
  // returns exactly the row of interest -- or the next key after it if the
  // target is gone, which is why the id is re-checked below.
  const listUrl = `${apiUrl.replace(/\/+$/, "")}/b2api/v3/b2_list_keys` +
    `?accountId=${encodeURIComponent(accountId)}&maxKeyCount=1` +
    `&startApplicationKeyId=${encodeURIComponent(target)}`;
  let listRes: Response;
  try {
    listRes = await fetch(listUrl, {
      headers: { "Authorization": token },
      signal: AbortSignal.timeout(globalArgs.timeoutMs),
    });
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `b2_list_keys request failed: ${String(cause)}`,
    };
  }
  if (!listRes.ok) {
    await listRes.body?.cancel();
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `unexpected HTTP ${listRes.status} from b2_list_keys`,
    };
  }

  let body: { keys?: unknown };
  try {
    body = await listRes.json();
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `b2_list_keys response was not JSON: ${String(cause)}`,
    };
  }

  const keys = body.keys;
  const row = Array.isArray(keys)
    ? (keys as Array<
      { applicationKeyId?: unknown; expirationTimestamp?: unknown }
    >)
      .find((k) => k.applicationKeyId === target)
    : undefined;
  if (row === undefined) {
    // Present in the manifest, absent from the account. An EXPIRED B2 key is
    // deleted outright rather than retained as expired, so this is the shape a
    // lapse actually takes here -- it must never read as "no expiry".
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail:
        `no key '${target}' on this account -- deleted, expired, or the manifest is stale`,
    };
  }

  const exp = row.expirationTimestamp;
  if (typeof exp !== "number" || exp === 0) {
    return onBehalfOf({
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail: "key is configured to never expire",
    });
  }
  // MILLISECONDS -> seconds. See the doc comment.
  return onBehalfOf(fromEpoch(exp / 1000, now, globalArgs));
}

/** A Scaleway secret key: a bare UUID, which is all `X-Auth-Token` takes. */
const SCW_SECRET_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A Scaleway access key id: `SCW` followed by 17 upper-case alphanumerics. */
const SCW_ACCESS_KEY_RE = /^SCW[A-Z0-9]{17}$/;

/**
 * Validate a `scaleway-key` subject: an access key id, never a secret.
 *
 * Same discipline as {@link parsePveSubject} and {@link parseB2Subject}, but
 * stricter, because the id has one fixed shape: anything else -- a secret-key
 * UUID above all -- is refused before it can be written into a resource.
 */
export function parseScalewaySubject(subject: string): string | null {
  return SCW_ACCESS_KEY_RE.test(subject) ? subject : null;
}

/**
 * Scaleway keeps a key's expiry server-side, so this reads the key's IAM record
 * rather than decoding anything.
 *
 * Unlike every other kind here, `subject` is REQUIRED: a Scaleway secret key
 * authenticates on its own (`X-Auth-Token`) and nothing in it, or in any
 * self-describing endpoint, says which access key it belongs to. A probe key
 * reporting on itself therefore names its own access key id as the subject.
 *
 * Status codes carry the distinctions B2 needed a capability list for:
 * 401 is a refused secret (an outage); 403 is a secret that authenticates but
 * lacks IAM read (a monitoring gap, which must not page anyone); 404 is a key
 * absent from the organization -- deleted, or never there -- which must read
 * as an outage, never as "no expiry".
 */
async function probeScalewayKey(
  secret: string,
  globalArgs: GlobalArgs,
  now: Date,
  subject?: string,
): Promise<ProbeResult> {
  if (!SCW_SECRET_RE.test(secret)) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: "secret is not a Scaleway secret key (a UUID)",
    };
  }
  const target = parseScalewaySubject(subject ?? "");
  if (target === null) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: (subject ?? "").length === 0
        ? "`subject` is required for scaleway-key: a secret key does not identify its own access key"
        : "`subject` is not a Scaleway access key id (`SCW` + 17 characters)",
    };
  }

  const url = `${globalArgs.scwBaseUrl.replace(/\/+$/, "")}` +
    `/iam/v1alpha1/api-keys/${encodeURIComponent(target)}`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { "X-Auth-Token": secret },
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
    await res.body?.cancel();
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: "Scaleway refused the probe secret (HTTP 401)",
    };
  }
  if (res.status === 403) {
    // Authenticated, but without IAM read -- see the doc comment.
    await res.body?.cancel();
    return {
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail:
        `probe secret authenticates but cannot read IAM, so the expiry of ${target} cannot be read (HTTP 403)`,
    };
  }
  if (res.status === 404) {
    await res.body?.cancel();
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail:
        `no key '${target}' in this organization -- deleted, or the manifest is stale`,
    };
  }
  if (!res.ok) {
    await res.body?.cancel();
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `unexpected HTTP ${res.status} from the IAM api-keys endpoint`,
    };
  }

  let body: { access_key?: unknown; expires_at?: unknown };
  try {
    body = await res.json();
  } catch (cause) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `api-keys response was not JSON: ${String(cause)}`,
    };
  }
  if (body.access_key !== target) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: `api-keys response was for a different key than ${target}`,
    };
  }

  const exp = body.expires_at;
  if (exp === null || exp === undefined || exp === "") {
    return {
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail: "key is configured to never expire",
    };
  }
  const ms = typeof exp === "string" ? Date.parse(exp) : NaN;
  if (Number.isNaN(ms)) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: "expires_at is not an ISO 8601 timestamp",
    };
  }
  return fromEpoch(ms / 1000, now, globalArgs);
}

// ---------------------------------------------------------------------------
// Scaleway plane sweep
// ---------------------------------------------------------------------------

/** A Scaleway organization id: a UUID. */
const SCW_ORG_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Page size for the api-keys listing; Scaleway's maximum. */
export const SCW_PAGE_SIZE = 100;
/**
 * Hard stop on pagination. 100 pages of 100 is far past any real organization;
 * a listing that has not ended by then is malformed, and reading it as complete
 * would be a silent under-count.
 */
export const SCW_MAX_PAGES = 100;

/** Longest key description carried into a resource. */
const MAX_DESCRIPTION = 200;

/** One API key from the listing, reduced to the fields a sweep reports. */
export type ScalewayKeyRow = z.infer<typeof SweepKeySchema>;

/**
 * List every API key in a Scaleway organization, following pagination.
 *
 * Only the fields in {@link ScalewayKeyRow} survive: the listing's record type
 * also has a `secret_key` field (filled only on create), and nothing outside the
 * allow-list is ever copied, so a provider change cannot leak one into a
 * resource. Status codes mirror {@link probeScalewayKey}, except 403 and 400:
 * for a sweep both mean it cannot see the plane at all, which is
 * `misconfigured`, not a quiet gap.
 */
export async function listScalewayKeys(
  secret: string,
  organizationId: string,
  globalArgs: Pick<GlobalArgs, "scwBaseUrl" | "timeoutMs">,
): Promise<
  { keys: Array<Omit<ScalewayKeyRow, "manifested">> } | {
    status: SweepStatus;
    detail: string;
  }
> {
  if (!SCW_SECRET_RE.test(secret)) {
    return {
      status: "authFailed",
      detail: "secret is not a Scaleway secret key (a UUID)",
    };
  }
  if (!SCW_ORG_RE.test(organizationId)) {
    return {
      status: "misconfigured",
      detail: organizationId === ""
        ? "`scwOrganizationId` is required for a sweep: the api-keys listing refuses a request without one"
        : "`scwOrganizationId` is not a UUID",
    };
  }
  const base = `${
    globalArgs.scwBaseUrl.replace(/\/+$/, "")
  }/iam/v1alpha1/api-keys`;
  const keys: Array<Omit<ScalewayKeyRow, "manifested">> = [];
  // A key minted mid-sweep can shift an offset page and repeat a record. Count
  // each access key once, so a repeat cannot stand in for a key never seen:
  // the total_count check below then reports the listing short.
  const seen = new Set<string>();
  for (let page = 1; page <= SCW_MAX_PAGES; page++) {
    const url =
      `${base}?organization_id=${encodeURIComponent(organizationId)}` +
      `&page=${page}&page_size=${SCW_PAGE_SIZE}&order_by=created_at_asc`;
    let res: Response;
    try {
      res = await fetch(url, {
        headers: { "X-Auth-Token": secret },
        signal: AbortSignal.timeout(globalArgs.timeoutMs),
      });
    } catch (cause) {
      return {
        status: "unreachable",
        detail: `request failed: ${String(cause)}`,
      };
    }
    if (res.status === 401) {
      await res.body?.cancel();
      return {
        status: "authFailed",
        detail: "Scaleway refused the sweep secret (HTTP 401)",
      };
    }
    if (res.status === 403) {
      await res.body?.cancel();
      return {
        status: "misconfigured",
        detail:
          "sweep secret authenticates but cannot list API keys in this organization (HTTP 403): it needs IAM read at organization scope",
      };
    }
    if (res.status === 400) {
      await res.body?.cancel();
      return {
        status: "misconfigured",
        detail:
          "the api-keys listing rejected the request (HTTP 400): check `scwOrganizationId`",
      };
    }
    if (!res.ok) {
      await res.body?.cancel();
      return {
        status: "unreachable",
        detail: `unexpected HTTP ${res.status} from the IAM api-keys listing`,
      };
    }
    let body: { api_keys?: unknown; total_count?: unknown };
    try {
      body = await res.json();
    } catch (cause) {
      return {
        status: "unreachable",
        detail: `api-keys listing was not JSON: ${String(cause)}`,
      };
    }
    if (!Array.isArray(body.api_keys) || typeof body.total_count !== "number") {
      return {
        status: "unreachable",
        detail: "api-keys listing lacks api_keys[] or total_count",
      };
    }
    for (const raw of body.api_keys as Array<Record<string, unknown>>) {
      const accessKey = raw?.access_key;
      if (typeof accessKey !== "string" || !SCW_ACCESS_KEY_RE.test(accessKey)) {
        return {
          status: "unreachable",
          detail: "api-keys listing holds a record without a valid access_key",
        };
      }
      if (seen.has(accessKey)) continue;
      seen.add(accessKey);
      const str = (v: unknown) => typeof v === "string" && v !== "" ? v : null;
      const app = str(raw.application_id);
      const user = str(raw.user_id);
      const exp = raw.expires_at;
      let expiresAt: string | null = null;
      if (exp !== null && exp !== undefined && exp !== "") {
        const ms = typeof exp === "string" ? Date.parse(exp) : NaN;
        if (Number.isNaN(ms)) {
          // Never read an unparseable expiry as "no expiry" or as a date.
          return {
            status: "unreachable",
            detail: `expires_at of ${accessKey} is not an ISO 8601 timestamp`,
          };
        }
        expiresAt = new Date(ms).toISOString();
      }
      const description = typeof raw.description === "string"
        ? raw.description.replace(/\s+/g, " ").trim().slice(0, MAX_DESCRIPTION)
        : "";
      keys.push({
        accessKey,
        bearerType: app ? "application" : user ? "user" : "unknown",
        bearerId: app ?? user,
        description,
        createdAt: str(raw.created_at),
        expiresAt,
      });
    }
    if (keys.length >= body.total_count || body.api_keys.length === 0) {
      if (keys.length < body.total_count) {
        return {
          status: "unreachable",
          detail:
            `api-keys listing ended at ${keys.length} of ${body.total_count} keys`,
        };
      }
      return { keys };
    }
  }
  return {
    status: "unreachable",
    detail: `api-keys listing did not end within ${SCW_MAX_PAGES} pages`,
  };
}

/**
 * Choose the `scaleway-key` entry whose secret lists the organization.
 *
 * Named explicitly, or -- when omitted -- inferred only if every `scaleway-key`
 * entry authenticates with the same secret, which is the normal shape (one
 * read-only probe key reporting on several subjects). Anything ambiguous is
 * refused rather than guessed.
 */
export function pickSweepCredential<
  C extends {
    id: string;
    kind: ProbeKind;
    secret?: string;
    secretRef?: { vault: string; key: string };
  },
>(credentials: C[], credentialId: string | undefined): C | string {
  const scw = credentials.filter((c) => c.kind === "scaleway-key");
  if (credentialId) {
    const named = credentials.find((c) => c.id === credentialId);
    if (!named) return `no credential entry with id '${credentialId}'`;
    if (named.kind !== "scaleway-key") {
      return `credential '${credentialId}' is ${named.kind}, not scaleway-key`;
    }
    return named;
  }
  if (scw.length === 0) {
    return "no scaleway-key entry to sweep with";
  }
  const sameAs = (c: C) =>
    c.secretRef
      ? `ref:${c.secretRef.vault}\u0000${c.secretRef.key}`
      : `inline:${c.secret}`;
  if (new Set(scw.map(sameAs)).size > 1) {
    return "scaleway-key entries use different secrets: pass `credentialId` to name the one to sweep with";
  }
  return scw[0];
}

/**
 * Compare a listing against the manifested subjects. Pure, so the decision of
 * what to report is testable without a network.
 */
export function compareScalewayPlane(
  keys: Array<Omit<ScalewayKeyRow, "manifested">>,
  manifested: ReadonlySet<string>,
): {
  keys: ScalewayKeyRow[];
  unmanifested: string[];
  noExpiry: string[];
  summary: string;
} {
  const rows = keys.map((k) => ({
    ...k,
    manifested: manifested.has(k.accessKey),
  }))
    .sort((a, b) => a.accessKey.localeCompare(b.accessKey));
  const unmanifested = rows.filter((k) => !k.manifested).map((k) =>
    k.accessKey
  );
  const noExpiry = rows.filter((k) => k.expiresAt === null).map((k) =>
    k.accessKey
  );
  const lines: string[] = [];
  for (const k of rows) {
    const flags = [
      ...(!k.manifested ? ["UNMANIFESTED"] : []),
      ...(k.expiresAt === null ? ["NO-EXPIRY"] : []),
    ];
    if (flags.length === 0) continue;
    const who = k.bearerId ? `${k.bearerType} ${k.bearerId}` : k.bearerType;
    const exp = k.expiresAt ? `expires ${k.expiresAt}` : "never expires";
    lines.push(
      `${flags.join(" ")} ${k.accessKey} — ${who}, ${exp}${
        k.description ? ` (${k.description})` : ""
      }`,
    );
  }
  return { keys: rows, unmanifested, noExpiry, summary: lines.join("\n") };
}

/**
 * One server token as `swamp access token list --json` describes it. Only these
 * fields are kept; the listing carries no secret, and anything else it grows is
 * dropped here rather than carried into a resource.
 */
export type ServeTokenRow = {
  name: string;
  state: string;
  effectiveState: string;
  expiresAt: string | null;
};

/** The serve token listing, or why it could not be read. */
export type ServeTokenListing = { tokens: ServeTokenRow[] } | {
  detail: string;
};

/** Longest CLI error carried into a resource and an alert body. */
const MAX_CLI_DETAIL = 300;

function capDetail(detail: string): string {
  const flat = detail.replace(/\s+/g, " ").trim();
  return flat.length > MAX_CLI_DETAIL
    ? `${flat.slice(0, MAX_CLI_DETAIL - 1)}…`
    : flat;
}

/**
 * Parse `swamp access token list --json` output.
 *
 * A body that is not an array of named rows is reported, never read as "no
 * tokens": an empty listing would turn every entry into a missing-token
 * outage, and a garbled one must not do that either. The raw output is never
 * echoed into the detail.
 *
 * Exported for tests.
 */
export function parseServeTokenList(stdout: string): ServeTokenListing {
  let body: unknown;
  try {
    body = JSON.parse(stdout);
  } catch {
    return { detail: "`swamp access token list --json` did not print JSON" };
  }
  if (!Array.isArray(body)) {
    return {
      detail: "`swamp access token list --json` did not print an array",
    };
  }
  const tokens: ServeTokenRow[] = [];
  for (const row of body as Array<Record<string, unknown>>) {
    if (typeof row?.name !== "string") {
      return { detail: "a token listing row has no name" };
    }
    tokens.push({
      name: row.name,
      state: typeof row.state === "string" ? row.state : "",
      effectiveState: typeof row.effectiveState === "string"
        ? row.effectiveState
        : "",
      expiresAt: typeof row.expiresAt === "string" ? row.expiresAt : null,
    });
  }
  return { tokens };
}

/** Runs a command and returns its exit code and output. Injected by tests. */
export type CommandRunner = (
  argv: string[],
  timeoutMs: number,
) => Promise<{ code: number; stdout: string; stderr: string }>;

const runCommand: CommandRunner = async (argv, timeoutMs) => {
  // The only subprocess in this model: a fixed `swamp access token list --json`,
  // whose sole variable parts are the configured binary and repo dir. No swamp
  // primitive exposes server token metadata to a model.
  // swamp-quality-ignore deno-command
  const output = await new Deno.Command(argv[0], {
    args: argv.slice(1),
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
    signal: AbortSignal.timeout(timeoutMs),
  }).output();
  const decoder = new TextDecoder();
  return {
    code: output.code,
    stdout: decoder.decode(output.stdout),
    stderr: decoder.decode(output.stderr),
  };
};

/**
 * Read the server token listing through the swamp CLI. Never throws: a CLI that
 * is missing, times out or exits non-zero is a listing `detail`, which the probe
 * reports as `unreachable` -- a statement about the monitor, not the token.
 */
export async function readServeTokenList(
  globalArgs: Pick<GlobalArgs, "swampBin" | "swampRepoDir" | "timeoutMs">,
  run: CommandRunner = runCommand,
): Promise<ServeTokenListing> {
  const argv = [globalArgs.swampBin, "access", "token", "list", "--json"];
  if (globalArgs.swampRepoDir) argv.push("--repo-dir", globalArgs.swampRepoDir);
  let result: Awaited<ReturnType<CommandRunner>>;
  try {
    result = await run(argv, globalArgs.timeoutMs);
  } catch (cause) {
    return { detail: capDetail(`could not run ${argv.join(" ")}: ${cause}`) };
  }
  if (result.code !== 0) {
    return {
      detail: capDetail(
        `${argv.join(" ")} exited ${result.code}: ${result.stderr}`,
      ),
    };
  }
  return parseServeTokenList(result.stdout);
}

/**
 * Validate a `swamp-serve-token` subject: a token NAME. A server token is
 * presented as `<name>.<secret>`, so a subject carrying a `.` is the token
 * itself pasted where its name belongs, and is refused before it can be written
 * into a resource.
 */
export function parseServeTokenSubject(subject: string): string | null {
  return /^[A-Za-z0-9_-]+$/.test(subject) ? subject : null;
}

/**
 * swamp serve keeps each server token's expiry in its own token store, and the
 * listing exposes it with no secret attached. So, unlike every other probe,
 * this one holds no credential: the entry names a token and the probe looks it
 * up.
 *
 * A token absent from the listing, or one the store marks as no longer
 * active, is an outage -- whoever presents it is refused today -- and must
 * never read as `noExpiry`. A token past its expiresAt is `expired` whatever
 * its state says.
 */
export function probeSwampServeToken(
  subject: string | undefined,
  listing: ServeTokenListing,
  now: Date,
  policy: { warnDays: number[]; criticalDays: number },
): ProbeResult {
  const name = parseServeTokenSubject(subject ?? "");
  if (name === null) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail: (subject ?? "").length === 0
        ? "`subject` is required for swamp-serve-token: it names the server token"
        : "`subject` is not a server token name (a `<name>.<secret>` token was pasted?)",
    };
  }
  if ("detail" in listing) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: listing.detail,
    };
  }
  const row = listing.tokens.find((t) => t.name === name);
  if (row === undefined) {
    return {
      status: "authFailed",
      expiresAt: null,
      daysRemaining: null,
      detail:
        `no server token '${name}' on this serve -- deleted, never minted, or the manifest is stale`,
    };
  }
  if (row.expiresAt === null) {
    return {
      status: "noExpiry",
      expiresAt: null,
      daysRemaining: null,
      detail: "server token reports no expiresAt -- unmonitorable by any clock",
    };
  }
  const ms = Date.parse(row.expiresAt);
  if (Number.isNaN(ms)) {
    return {
      status: "unreachable",
      expiresAt: null,
      daysRemaining: null,
      detail: "expiresAt is not an ISO 8601 timestamp",
    };
  }
  const result = fromEpoch(ms / 1000, now, policy);
  if (result.status !== "expired" && row.effectiveState !== "active") {
    return {
      ...result,
      status: "authFailed",
      daysRemaining: null,
      detail: `server token '${name}' is ${
        row.effectiveState || "in an unknown state"
      }, not active`,
    };
  }
  return result;
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
    case "b2-key":
      return (secret, globalArgs, now, subject) =>
        probeB2Key(secret, globalArgs, now, subject);
    case "scaleway-key":
      return (secret, globalArgs, now, subject) =>
        probeScalewayKey(secret, globalArgs, now, subject);
    case "swamp-serve-token":
      // No secret: the listing is the whole input. Read it through the
      // audit's shared listing when there is one, otherwise on its own.
      return async (_secret, globalArgs, now, subject, deps) =>
        probeSwampServeToken(
          subject,
          await (deps?.serveTokens?.() ?? readServeTokenList(globalArgs)),
          now,
          globalArgs,
        );
    default: {
      const unreachable: never = kind;
      throw new Error(`no probe implemented for kind: ${String(unreachable)}`);
    }
  }
}

/**
 * The credential-expiry model. `audit` probes every configured credential,
 * writes one `credential` resource each plus an `audit` summary, and refuses the
 * whole run rather than report a partial one. `sweep` lists a Scaleway
 * organization's keys and reports the ones the model does not name, and the
 * ones with no expiry. Both are read-only.
 */
export const model = {
  type: "@sntxrr/credential-expiry",
  description:
    "Probe the credentials a fleet actually holds and report how long each has left, distinguishing expiry from an outage in progress",
  version: "2026.10.22.1",
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
    {
      toVersion: "2026.09.30.1",
      description:
        "Adds the `scaleway-key` probe kind and the `scwBaseUrl` global argument, and declares the `b2-key` kind shipped in 2026.09.09.1 without a model version bump. Nothing to migrate: the credential and audit resource schemas are unchanged. To monitor a Scaleway API key, add an entry with `kind: scaleway-key` whose secret is a read-only probe key's secret (IAM read at organization scope) and whose `subject` is the access key id being watched -- required, because a Scaleway secret does not identify its own access key.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.20.1",
      description:
        "Adds the optional `secretRef: {vault, key}` field and the `unresolved` status. Nothing to migrate: `secret` still works exactly as before. An entry that names `secretRef` instead is read by the method itself, so a missing or unreadable vault item is reported as that entry's `unresolved` status (counted in the new `unresolved` audit field, and alerted immediately like `authFailed`) rather than failing the whole audit before any credential is probed. Set exactly one of `secret` and `secretRef` per entry.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.20.2",
      description:
        "Adds the `swamp-serve-token` probe kind and the `swampBin` / `swampRepoDir` global arguments. Nothing to migrate: the credential and audit resource schemas are unchanged. To monitor a swamp serve server token, add an entry with `kind: swamp-serve-token`, no `secret` or `secretRef`, and `subject` set to the token's name; the probe reads its expiresAt from `swamp access token list --json`, which carries no secret. Run the audit where the served repository is, and set `swampRepoDir` to it.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.22.1",
      description:
        "Adds the read-only `sweep` method, the `scwOrganizationId` global argument and the `sweep` resource. " +
        "Nothing to migrate: `audit`, and the credential and audit resource schemas, are unchanged. " +
        "The sweep lists every API key in a Scaleway organization and reports the keys no `scaleway-key` entry names (`unmanifested`) and the keys with no expiry (`noExpiry`), as instance `sweep-scaleway`. " +
        "To use it, set `scwOrganizationId` and run `sweep`; it authenticates as a `scaleway-key` entry's secret (named by the `credentialId` argument, or inferred when every such entry shares one secret), which needs IAM read at organization scope. " +
        "A credential id that normalises to `sweep-scaleway` is now refused by preflight, as `current` already was.",
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
    "sweep": {
      description:
        "One sweep of a provider's whole key plane: keys missing from the manifest, and keys with no expiry",
      schema: SweepSchema,
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
          vaultService?: VaultLike;
          redactor?: { addSecret: (value: string) => void };
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

        logger.info("Auditing {total} credentials", {
          total: globalArgs.credentials.length,
        });

        const now = new Date();
        const checkedAt = now.toISOString();
        const handles: Array<{ name: string }> = [];
        const counts: Record<Status, number> = {
          authFailed: 0,
          unresolved: 0,
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

        // Read at most once per audit, and only if an entry needs it.
        let serveTokens: Promise<ServeTokenListing> | undefined;
        const deps: ProbeDeps = {
          serveTokens: () => serveTokens ??= readServeTokenList(globalArgs),
        };

        for (const cred of globalArgs.credentials) {
          // A switch rather than a ternary chain: the compiler now fails the
          // build if a probe kind is added to PROBE_KINDS without a probe
          // behind it, instead of quietly routing it to whichever branch
          // happened to be last.
          const resolved = SECRETLESS_KINDS.has(cred.kind)
            ? { secret: "" }
            : await resolveSecret(
              cred,
              context.vaultService,
              context.redactor,
            );
          const result: ProbeResult = "secret" in resolved
            ? await probeFor(cred.kind)(
              resolved.secret,
              globalArgs,
              now,
              cred.subject,
              deps,
            )
            : {
              status: "unresolved",
              expiresAt: null,
              daysRemaining: null,
              detail: resolved.detail,
            };

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
          if (result.status === "unresolved") {
            // The detail names a vault and key, never a value.
            logger.warn("{id}: secret could not be read: {detail}", {
              id: cred.id,
              detail: result.detail,
            });
          } else {
            logger.info("{id}: {status}", {
              id: cred.id,
              status: result.status,
            });
          }

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
          counts.authFailed + counts.unresolved + counts.expired +
              counts.critical + counts.warn + counts.unreachable > 0;

        logger.info(
          "{total} credentials probed; {actionable}",
          {
            total: globalArgs.credentials.length,
            actionable: actionable ? "action needed" : "all clear",
          },
        );

        const { notify, reason } = shouldNotify(outcomes, globalArgs);

        handles.push(
          await context.writeResource("audit", AUDIT_INSTANCE, {
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
    sweep: {
      description:
        "List every API key in the Scaleway organization and report the ones no scaleway-key entry names, and the ones with no expiry",
      arguments: z.object({
        credentialId: z.string().optional().describe(
          "Id of the `scaleway-key` entry whose secret lists the organization. Omit it " +
            "when every `scaleway-key` entry shares one secret.",
        ),
      }),
      // Every failure is a written resource with `notify: true`, never a throw:
      // a sweep that cannot see the plane must say so through the same alert
      // path as a finding, or a lapsed probe key would turn it back into the
      // silence it exists to end.
      execute: async (
        args: { credentialId?: string },
        context: {
          globalArgs: GlobalArgs;
          logger: Logger;
          writeResource: (
            specName: string,
            name: string,
            data: Record<string, unknown>,
          ) => Promise<{ name: string }>;
          vaultService?: VaultLike;
          redactor?: { addSecret: (value: string) => void };
        },
      ) => {
        const { globalArgs, logger } = context;
        const checkedAt = new Date().toISOString();
        const manifested = new Set(
          globalArgs.credentials
            .filter((c) => c.kind === "scaleway-key")
            .map((c) => parseScalewaySubject(c.subject))
            .filter((s): s is string => s !== null),
        );

        const write = async (
          r: {
            status: SweepStatus;
            detail: string;
            credentialId: string | null;
            total: number | null;
            unmanifested?: string[];
            noExpiry?: string[];
            keys?: ScalewayKeyRow[];
            summary?: string;
          },
        ) => {
          const unmanifested = r.unmanifested ?? [];
          const noExpiry = r.noExpiry ?? [];
          const reason = r.status === "findings"
            ? [
              ...(unmanifested.length ? ["unmanifested"] : []),
              ...(noExpiry.length ? ["noExpiry"] : []),
            ].join("+")
            : r.status === "ok"
            ? ""
            : r.status;
          logger.info("Scaleway sweep: {status} ({total} keys)", {
            status: r.status,
            total: r.total ?? "unknown",
          });
          return {
            dataHandles: [
              await context.writeResource("sweep", SWEEP_INSTANCE, {
                checkedAt,
                plane: "scaleway",
                status: r.status,
                detail: r.detail,
                credentialId: r.credentialId,
                total: r.total,
                manifested: manifested.size,
                unmanifested,
                noExpiry,
                keys: r.keys ?? [],
                notify: r.status !== "ok",
                notifyReason: reason,
                summary: r.summary ?? (r.status === "ok" ? "" : r.detail),
              }),
            ],
          };
        };

        const picked = pickSweepCredential(
          globalArgs.credentials,
          args.credentialId,
        );
        if (typeof picked === "string") {
          return await write({
            status: "misconfigured",
            detail: picked,
            credentialId: args.credentialId ?? null,
            total: null,
          });
        }

        // Checked before the vault read: a sweep that cannot list anything has
        // no reason to read a secret.
        if (!SCW_ORG_RE.test(globalArgs.scwOrganizationId)) {
          return await write({
            status: "misconfigured",
            detail: globalArgs.scwOrganizationId === ""
              ? "`scwOrganizationId` is required for a sweep: the api-keys listing refuses a request without one"
              : "`scwOrganizationId` is not a UUID",
            credentialId: picked.id,
            total: null,
          });
        }

        const resolved = await resolveSecret(
          picked,
          context.vaultService,
          context.redactor,
        );
        if (!("secret" in resolved)) {
          logger.warn("{id}: secret could not be read: {detail}", {
            id: picked.id,
            detail: resolved.detail,
          });
          return await write({
            status: "unresolved",
            detail: resolved.detail,
            credentialId: picked.id,
            total: null,
          });
        }

        const listing = await listScalewayKeys(
          resolved.secret,
          globalArgs.scwOrganizationId,
          globalArgs,
        );
        if (!("keys" in listing)) {
          return await write({
            status: listing.status,
            detail: listing.detail,
            credentialId: picked.id,
            total: null,
          });
        }

        const cmp = compareScalewayPlane(listing.keys, manifested);
        return await write({
          status: cmp.unmanifested.length + cmp.noExpiry.length > 0
            ? "findings"
            : "ok",
          detail: "",
          credentialId: picked.id,
          total: listing.keys.length,
          ...cmp,
        });
      },
    },
  },
};
