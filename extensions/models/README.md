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

The GitHub expiry is a header, not a body field, which is why that probe looks like a
liveness check rather than an API call for data. A token with no expiry simply omits it.

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
  warnDays: [30, 14, 7]
  criticalDays: 3
```

Always supply `secret` through `vault.get()`. The value is marked sensitive, is never
logged, and is never written to a resource — only the id, the expiry and the status leave
the method.

## Resources

`credential` — one per probed credential: `status`, `expiresAt`, `daysRemaining`, `note`,
`detail`. Named by the credential's `id`, so it maps straight onto a manifest entry.

`audit` — written as instance `current`. Counts per status, `soonestDays` / `soonestId`, an
`actionable` boolean, and a `summary` string of one line per non-ok credential, ready to drop
into a notification body.

Gate a notification on `actionable`, not on a raw count. `daysRemaining` is floored, never
rounded: 0.9 days left reads as `0`, because rounding up would let a credential expire on a
day the report called safe.
