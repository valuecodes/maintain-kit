import assert from "node:assert/strict";
import { test } from "node:test";
import { excerpt, redact } from "./redact.ts";

test("redact masks credentials in URLs, settings and token shapes", () => {
  assert.equal(
    redact("registry=https://user:pw@npm.example.com/x"),
    "registry=https://***@npm.example.com/x",
  );
  assert.equal(
    redact("//npm.example.com/:_authToken=abc"),
    "//npm.example.com/:_authToken=***",
  );
  assert.equal(redact("  _password=secret"), "  _password=***");
  assert.equal(redact('  "npmToken": "abc",'), '  "npmToken": "***"');
  assert.equal(
    redact(
      `token ${"npm_".padEnd(40, "a")} and ${"ghp_".padEnd(40, "b")} and github_pat_${"c".repeat(22)}`,
    ),
    "token *** and *** and ***",
  );
  assert.equal(redact("plain=value\nname=x"), "plain=value\nname=x");
});

// The shape of a stateless installation token: a JWT with `-` and `_` in its
// segments, about 520 characters, ending in `end`.
const jwt = (end: string): string =>
  `ghs_eyJhbGciOiJSUzI1NiJ9.${"eyJ-p_".repeat(60)}.${"s-_".repeat(80)}${end}`;

test("redact masks whole stateless installation tokens", () => {
  assert.ok(jwt("x").length > 500);
  assert.equal(redact(`token ${jwt("x")} done`), "token *** done");
  assert.equal(redact(`(${jwt("-")}), next`), "(***), next");
  assert.equal(redact(`[${jwt("_")}]`), "[***]");
  assert.equal(redact(`ghs_${"a".repeat(36)}`), "***");
  assert.equal(
    redact(`cache ${"ghp_".padEnd(40, "b")}.json`),
    "cache ***.json",
  );
});

test("excerpt titles, caps and indents a block", () => {
  assert.equal(excerpt("T", "a\nb\n"), "\n**T**\n\n    a\n    b\n\n");
  assert.equal(excerpt("T", "a"), "\n**T**\n\n    a\n\n");
  assert.equal(excerpt("T", ""), "\n**T**\n\n\n");
  const long = excerpt("T", "x".repeat(30_000));
  assert.equal(long.length, "\n**T**\n\n    ".length + 20_000 + 2);
});
