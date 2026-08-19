# swamp-credential-expiry

Swamp extension providing **`@sntxrr/credential-expiry`** — probe the credentials an
automation fleet actually holds and report how long each has left.

Expiry is invisible until something stops working, and the thing that stops working is
usually the unattended job nobody watches. This turns that into a scheduled check with one
useful property: it reads **the same secret the consuming job uses**, so a deployment left
behind on a superseded credential shows up as its own finding rather than hiding behind a
healthy-looking registry.

| | |
| --- | --- |
| Model | `@sntxrr/credential-expiry` |
| Probes | `jwt` (decode the `exp` claim), `github-pat` (read GitHub's token-expiration response header) |
| Writes | `credential` per credential, `audit` summary as `current` |
| Network | Read-only. Every probe is a decode or a `GET`. |

## Why the statuses are not collapsed

Most expiry checks report a number of days and a boolean. Three distinctions are worth
keeping separate, because collapsing any of them produces a worse alert:

- **`noExpiry` is not `ok`.** A credential with no expiry is not healthy, it is
  *unmonitorable* — strictly worse than one about to lapse. It is reported separately and
  deliberately excluded from `actionable`: standing design debt belongs in a review, not in a
  nightly page. A page that fires every night over an unchanged fact gets muted.
- **`authFailed` is not `expired`.** A credential refused *right now* is an outage in
  progress; thresholds do not apply to it. One that lapsed at some point may already have
  been replaced everywhere that matters.
- **`unreachable` is neither.** Otherwise a DNS blip reads as a dead credential.

`daysRemaining` is floored, never rounded. 0.9 days left reads as `0`, because rounding up
would let a credential expire on a day the report called safe.

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

See [`extensions/models/README.md`](extensions/models/README.md) for the full reference.

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

Always supply `secret` through `vault.get()`. It is marked sensitive, is never logged, and
never reaches a resource — only the id, the expiry and the status leave the method.

## Development

```bash
deno check extensions/models/credential_expiry.ts
deno test  extensions/models/credential_expiry_test.ts
```

## License

MIT
