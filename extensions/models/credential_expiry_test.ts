// extensions/models/credential_expiry_test.ts
import { assertEquals } from "jsr:@std/assert@1";
import {
  classify,
  decodeJwtExp,
  parseGithubExpiryHeader,
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
