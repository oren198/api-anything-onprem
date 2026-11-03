/** An internal deployment's allowlist (docs/INTERNAL.md): what it admits, what it never does, and the config it travels with. */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { launchOf } from "../src/clients.js";
import { lanAddress, publicAddress, refusePrivateHop, resolver } from "../src/http.js";
import { hostInternal, ipInternal, parseInternalHosts, setInternalHosts } from "../src/internal.js";
import { registryBase } from "../src/registry.js";
import { REGISTRY_API } from "../src/registry-api.js";
import { badAddress } from "../src/vet.js";

const saved = { ...process.env };
const lookup = resolver.lookup;
afterEach(() => {
  process.env = { ...saved };
  resolver.lookup = lookup;
  setInternalHosts(undefined);
});

const answers = (map: Record<string, string[]>) => {
  resolver.lookup = async (host: string) => (map[host] ?? []).map((address) => ({ address }));
};

test("parse: globs, exact hosts, v4 and v6 CIDRs; a typo throws", () => {
  const l = parseInternalHosts(" *.corp.example, app.corp.internal ,10.0.0.0/8, fd00::/8 ");
  assert.deepEqual(l.globs, ["*.corp.example", "app.corp.internal"]);
  assert.equal(l.cidrs.length, 2);
  assert.deepEqual(parseInternalHosts(""), { globs: [], cidrs: [] });
  assert.throws(() => parseInternalHosts("10.0.0.0/33"), /no CIDR/);
  assert.throws(() => parseInternalHosts("http://x.corp"), /neither a host/);
});

test("host globs: *.x matches hosts under x, not x itself nor a lookalike", () => {
  const l = parseInternalHosts("*.corp.example,app.corp.internal");
  assert.ok(hostInternal("tools.corp.example", l));
  assert.ok(hostInternal("A.B.Corp.Example.", l));
  assert.ok(hostInternal("app.corp.internal", l));
  assert.ok(!hostInternal("corp.example", l));
  assert.ok(!hostInternal("evilcorp.example", l));
  assert.ok(!hostInternal("x.app.corp.internal", l));
});

test("CIDRs: v4, v6 and v4-mapped v6", () => {
  const l = parseInternalHosts("10.20.0.0/16,fd12:3456::/32");
  assert.ok(ipInternal("10.20.255.1", l));
  assert.ok(!ipInternal("10.21.0.1", l));
  assert.ok(ipInternal("::ffff:10.20.1.1", l));
  assert.ok(ipInternal("fd12:3456:1::9", l));
  assert.ok(!ipInternal("fd12:3457::9", l));
  assert.ok(!ipInternal("not-an-ip", l));
});

test("lanAddress: the private LAN ranges only", () => {
  for (const ip of ["10.1.1.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fd00::1", "::ffff:10.0.0.1"])
    assert.ok(lanAddress(ip), ip);
  for (const ip of ["127.0.0.1", "169.254.169.254", "::1", "fe80::1", "8.8.8.8", "224.0.0.1"])
    assert.ok(!lanAddress(ip), ip);
});

test("badAddress: unchanged by default; an allowlisted internal host passes, still https only", () => {
  assert.match(badAddress("https://app.corp.internal/x")!, /no public host/);
  assert.match(badAddress("https://10.0.0.5/x")!, /no public host/);
  process.env.API_ANYTHING_INTERNAL_HOSTS = "app.corp.internal,10.0.0.0/24";
  assert.equal(badAddress("https://app.corp.internal/x"), undefined);
  assert.equal(badAddress("https://10.0.0.5/x"), undefined);
  assert.match(badAddress("http://app.corp.internal/x")!, /is not https/);
  assert.match(badAddress("https://other.corp.internal/x")!, /no public host/);
  assert.match(badAddress("https://10.0.1.5/x")!, /no public host/);
});

test("publicAddress: a listed host reaches a LAN address; others, and loopback or metadata, stay refused", async () => {
  answers({
    "tools.corp.example": ["10.1.2.3"],
    "loop.corp.example": ["127.0.0.1"],
    "meta.corp.example": ["169.254.169.254"],
    "rogue.example.com": ["10.1.2.3"],
    "db.example.com": ["10.9.0.4"],
  });
  assert.match((await publicAddress("https://tools.corp.example/"))!, /no public host/);
  process.env.API_ANYTHING_INTERNAL_HOSTS = "*.corp.example";
  assert.equal(await publicAddress("https://tools.corp.example/"), undefined);
  assert.match((await publicAddress("https://loop.corp.example/"))!, /127\.0\.0\.1/);
  assert.match((await publicAddress("https://meta.corp.example/"))!, /169\.254\.169\.254/);
  assert.match((await publicAddress("https://rogue.example.com/"))!, /non-public address 10\.1\.2\.3/);
  // a CIDR admits any host resolving inside it, and only inside it
  process.env.API_ANYTHING_INTERNAL_HOSTS = "10.9.0.0/16";
  assert.equal(await publicAddress("https://db.example.com/"), undefined);
  assert.match((await publicAddress("https://rogue.example.com/"))!, /non-public address 10\.1\.2\.3/);
});

test("refusePrivateHop: a redirect to a listed host is followed, one to an unlisted private host is not", async () => {
  answers({ "a.corp.example": ["10.0.0.7"], "b.example.com": ["192.168.1.9"] });
  process.env.API_ANYTHING_INTERNAL_HOSTS = "*.corp.example";
  await refusePrivateHop({ method: "GET", url: "https://a.corp.example/next", headers: {} }, 302);
  await assert.rejects(
    refusePrivateHop({ method: "GET", url: "https://b.example.com/next", headers: {} }, 302),
    /not following the HTTP 302/,
  );
});

test("launchOf forwards the registry, internal hosts and the extra CA file to the MCP server", () => {
  const l = launchOf("/x/cli.js", [], {
    API_ANYTHING_HOME: "/h",
    API_ANYTHING_REGISTRY: "https://aa.corp.example",
    API_ANYTHING_INTERNAL_HOSTS: "*.corp.example",
    NODE_EXTRA_CA_CERTS: "/etc/ca.pem",
    API_ANYTHING_OTHER: "no",
    SECRET: "no",
  });
  assert.deepEqual(l.env, {
    API_ANYTHING_HOME: "/h",
    API_ANYTHING_REGISTRY: "https://aa.corp.example",
    API_ANYTHING_INTERNAL_HOSTS: "*.corp.example",
    NODE_EXTRA_CA_CERTS: "/etc/ca.pem",
  });
});

test("registryBase: env, then settings.json registry, then the public one with a warning when internal hosts are set", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "aa-internal-"));
  process.env.API_ANYTHING_HOME = dir;
  delete process.env.API_ANYTHING_REGISTRY;
  delete process.env.API_ANYTHING_INTERNAL_HOSTS;
  assert.equal(registryBase(), REGISTRY_API);
  writeFileSync(join(dir, "settings.json"), JSON.stringify({ share: false, registry: "https://aa.corp.example/" }));
  assert.equal(registryBase(), "https://aa.corp.example");
  process.env.API_ANYTHING_REGISTRY = "https://env.corp.example";
  assert.equal(registryBase(), "https://env.corp.example");
  writeFileSync(join(dir, "settings.json"), JSON.stringify({ registry: "http://aa.corp.example" }));
  delete process.env.API_ANYTHING_REGISTRY;
  assert.throws(() => registryBase(), /must be https/);
  writeFileSync(join(dir, "settings.json"), "{}");
  process.env.API_ANYTHING_INTERNAL_HOSTS = "*.corp.example";
  const written: string[] = [];
  t.mock.method(process.stderr, "write", (s: string) => {
    written.push(s);
    return true;
  });
  assert.equal(registryBase(), REGISTRY_API);
  assert.match(written.join(""), /INTERNAL_HOSTS is set but no registry is/);
});
