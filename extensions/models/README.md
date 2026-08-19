# @sntxrr/credential-expiry

Probe the credentials an automation fleet actually holds, and report how long each has left.

Expiry is invisible until something stops working, and the thing that stops working is
usually the unattended job nobody watches. This model turns that into a scheduled check with
one useful property: it reads **the same secret the consuming job uses**, so a deployment
left behind on a superseded credential shows up as its own finding rather than hiding behind
a healthy-looking registry.

Read-only by construction. Every probe is a decode or a `GET`; there is no method that can
create, rotate or revoke anything.

## Probes

| `kind` | How the expiry is read |
|---|---|
| `jwt` | Decodes the `exp` claim locally. No network call, no verification — verification is the server's job. |
| `github-pat` | `GET {apiBaseUrl}/user` and reads the `github-authentication-token-expiration` **response header**. |
| `gitlab-pat` | `GET {gitlabBaseUrl}/api/v4/personal_access_tokens/self` and reads `expires_at` from the body. |

The GitHub expiry is a header, not a body field, which is why that probe looks like a
liveness check rather than an API call for data. A token with no expiry simply omits it.

The GitLab probe works for **project and group access tokens too** — GitLab implements
both as personal tokens belonging to a bot user, so they answer the same endpoint.

Two GitLab-specific details worth knowing, because both would otherwise produce a wrong
alert:

- **`403` is not a dead credential.** GitLab answers an invalid, revoked or expired token
  with `401`, but answers a perfectly good token that merely lacks the `api`/`read_api`
  scope to introspect *itself* with `403 insufficient_scope`. Collapsing the two into
  `authFailed` would page somebody over a `read_registry` token that is working exactly as
  intended, so a `403` is reported as `noExpiry` — unmonitorable, and fixable by widening
  the scope.
- **`expires_at` is a bare date**, so the moment of death is chosen rather than read. It is
  anchored to UTC midnight at the *start* of that date, the earliest instant the token
  could stop working. Anchoring to the end of the day would buy a day of headroom that may
  not exist.

## Statuses

Ordered worst-first.

| Status | Meaning |
|---|---|
| `authFailed` | Refused **now** (401/403), or a value that will not parse. An outage in progress, not a warning — thresholds do not apply. |
| `expired` | Past its expiry. |
| `critical` | At or below `criticalDays`. |
| `warn` | Within the widest `warnDays` threshold. |
| `noExpiry` | Authenticates, but carries no expiry at all. |
| `unreachable` | The probe could not complete. A statement about the network, not the credential. |
| `ok` | Nothing to do. |

Three of these distinctions exist because collapsing them produces a worse alert:

- **`noExpiry` is not `ok`.** A credential with no expiry is not healthy, it is
  *unmonitorable* — strictly worse than one about to lapse, and exactly the class this model
  exists because of. It is reported separately and deliberately **excluded** from
  `actionable`: it is standing design debt for a review, not a nightly page. A page that
  fires every night over an unchanged fact is one that gets muted.
- **`authFailed` is not `expired`.** A credential being refused right now is an outage.
  A credential that lapsed at some point may already have been replaced everywhere.
- **`unreachable` is not either.** Otherwise a DNS blip reads as a dead credential.

## Alerting: gate on `notifyToday`, not on `actionable`

`actionable` says something needs a human *eventually*. It is the wrong gate for a daily
run: a credential 29 days out is actionable for 29 consecutive days, and an alert that
repeats an unchanged fact every day for a month is one that gets filtered — at which point
the monitor has made things worse than no monitor.

`notifyToday` is the gate. It fires:

- **immediately** for anything outage-shaped (`authFailed`, `expired`, `unreachable`);
- on the **exact day** a `warnDays` threshold is crossed;
- **every day** once inside `criticalDays`;
- **never** for `noExpiry` or `ok`.

A 90-day credential therefore produces four notifications in its life rather than thirty.
`notifyReason` carries which of those applied, for the subject line.

## Usage

### Install

```bash
swamp extension pull @sntxrr/credential-expiry
```

### Define what to watch

One entry per credential. The `id` should match the manifest entry it
corresponds to, so a finding points straight at the thing that will break.

```yaml
type: '@sntxrr/credential-expiry'
name: credential-expiry
globalArguments:
  credentials:
    - id: connect-token/deploy-bot
      kind: jwt
      secret: '${{ vault.get(store, deploy-bot/token) }}'
      note: every scheduled deploy resolves its secrets through this
    - id: pat/dependency-sweep
      kind: github-pat
      secret: '${{ vault.get(store, sweep/pat) }}'
      note: the weekly sweep alerts only on success, so expiry is silent
    - id: gitlab/mirror-sync
      kind: gitlab-pat
      secret: '${{ vault.get(store, mirror/token) }}'
      note: project access token the nightly mirror pushes with
  warnDays: [30, 14, 7]
  criticalDays: 3
```

Always supply `secret` through `vault.get()`. The value is marked sensitive, is
never logged, and is never written to a resource — only the id, the expiry and
the status leave the method.

### Run an audit

```bash
swamp model @sntxrr/credential-expiry method run audit credential-expiry

# the whole picture, worst first
swamp model get credential-expiry --json
```

### Ask the questions that matter

The point of separate statuses is that each one supports a different question.

```bash
# what breaks in the next fortnight?
swamp data query credential-expiry 'attributes.daysRemaining < 14'

# what is already broken right now?
swamp data query credential-expiry 'attributes.status == "authFailed"'

# what can no clock ever warn us about? (the standing design debt)
swamp data query credential-expiry 'attributes.status == "noExpiry"'
```

### Schedule it, and notify only when it matters

Gate the notify step on `notifyToday`, not on `actionable` — see the section
above for why the difference is the whole point.

```yaml
name: credential-expiry-daily
steps:
  - name: audit
    model: credential-expiry
    method: audit

  - name: notify
    model: apprise
    method: notify
    if: '${{ data.latest("credential-expiry", "audit").attributes.notifyToday }}'
    inputs:
      title: '${{ data.latest("credential-expiry", "audit").attributes.notifyReason }}'
      body: '${{ data.latest("credential-expiry", "audit").attributes.summary }}'
```

### Self-managed and Enterprise instances

Both host arguments take the instance root. `gitlabBaseUrl` must **not** include
the `/api/v4` suffix — the probe appends it.

```yaml
globalArguments:
  apiBaseUrl: https://github.example.com/api/v3
  gitlabBaseUrl: https://gitlab.example.com
  timeoutMs: 15000
```

## Resources

`credential` — one per probed credential: `status`, `expiresAt`, `daysRemaining`,
`note`, `detail`. Named by the credential's `id`, normalised into a safe instance
name, so it maps straight onto a manifest entry. Two ids that would normalise to
the same name abort the run rather than silently overwrite one another.

`audit` — written as instance `current`. Counts per status, `soonestDays` /
`soonestId`, the `actionable` and `notifyToday` booleans, `notifyReason`, and a
`summary` string of one line per non-ok credential, ready to drop into a
notification body.

`daysRemaining` is floored, never rounded: 0.9 days left reads as `0`, because
rounding up would let a credential expire on a day the report called safe.

## Development

```bash
~/.swamp/deno/deno check extensions/models/credential_expiry.ts
~/.swamp/deno/deno test --allow-net extensions/models/credential_expiry_test.ts
```

Tests mock `fetch`; there are no live calls, and no probe in this model can
mutate anything.

## License

MIT
