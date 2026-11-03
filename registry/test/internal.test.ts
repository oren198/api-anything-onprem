/** An internal deployment of the registry (docs/INTERNAL.md): where it reads a network from, and which internal sites it takes. */
import assert from "node:assert/strict";
import { afterEach, describe, test } from "node:test";
import { setInternalHosts } from "../../src/internal.js";
import { clientIp, networkSource, networksOf } from "../src/auth.js";
import { evidence, install, op, registry, report, send } from "./helpers.js";

afterEach(() => setInternalHosts(undefined));

describe("network identity", () => {
  const h = (o: Record<string, string>) => new Headers(o);

  test("networkSource reads TRUSTED_IP_HEADER, TRUSTED_PROXY_HOPS and BEHIND_CLOUDFLARE", () => {
    assert.deepEqual(networkSource({}), { cloudflare: true });
    assert.deepEqual(
      networkSource({ TRUSTED_IP_HEADER: " X-Forwarded-For ", TRUSTED_PROXY_HOPS: "2", BEHIND_CLOUDFLARE: "false" }),
      {
        trustedIpHeader: "x-forwarded-for",
        trustedHops: 2,
        cloudflare: false,
      },
    );
    assert.deepEqual(networkSource({ TRUSTED_PROXY_HOPS: "0", BEHIND_CLOUDFLARE: "0" }), { cloudflare: false });
  });

  test("a trusted header gives its nth address from the right; what a client prepends is ignored", () => {
    const xff = h({ "x-forwarded-for": "6.6.6.6, 10.1.2.3, 10.9.9.9", "cf-connecting-ip": "1.1.1.1" });
    assert.equal(clientIp(xff, { trustedIpHeader: "x-forwarded-for" }), "10.9.9.9");
    assert.equal(clientIp(xff, { trustedIpHeader: "x-forwarded-for", trustedHops: 2 }), "10.1.2.3");
    assert.equal(clientIp(xff, { trustedIpHeader: "x-forwarded-for", trustedHops: 9 }), "");
    assert.equal(clientIp(h({}), { trustedIpHeader: "x-forwarded-for" }), "");
    assert.equal(clientIp(xff, {}), "1.1.1.1");
    assert.equal(clientIp(xff, { cloudflare: false }), "", "off Cloudflare, cf-connecting-ip is the client's to forge");
  });

  test("networksOf ignores request.cf off Cloudflare and tells /24s apart by the trusted header", async () => {
    const req = (ip: string) => {
      const r = new Request("https://r.test/", { headers: { "x-real-ip": ip } });
      Object.defineProperty(r, "cf", { value: { asn: 64500 } });
      return r;
    };
    const src = { trustedIpHeader: "x-real-ip", cloudflare: false };
    const [a, b, c] = await Promise.all(
      [req("10.1.1.5"), req("10.1.1.9"), req("10.2.0.1")].map((r) => networksOf(r, "s", src)),
    );
    assert.equal(a!.network, b!.network);
    assert.notEqual(a!.network, c!.network);
    const viaAsn = await Promise.all([req("10.1.1.5"), req("10.2.0.1")].map((r) => networksOf(r, "s")));
    assert.equal(viaAsn[0]!.network, viaAsn[1]!.network, "behind Cloudflare the ASN still counts");
  });
});

const internalSite = { name: "corp-internal", domain: "corp.internal", baseUrl: "https://app.corp.internal" };
const internalOp = op({
  request: { method: "GET", url: "https://app.corp.internal/api/search?q=dune", headers: {} },
  trigger: { url: "https://app.corp.internal/search?q={q}" },
  match: { host: "app.corp.internal", path: "/api/search" },
});
const body = { site: internalSite, operation: internalOp, evidence };

describe("internal sites", () => {
  test("refused unless the registry lists the host in INTERNAL_HOSTS", async () => {
    const { env } = registry();
    const r = await send(env, "POST", "/v1/versions", { as: install(), body });
    assert.equal(r.status, 422, r.text);
    assert.match(r.text, /no public host \(app\.corp\.internal\)/);
    const other = registry({ INTERNAL_HOSTS: "*.other.internal" }).env;
    assert.equal((await send(other, "POST", "/v1/versions", { as: install(), body })).status, 422);
  });

  test("listed, it is a candidate, and goes live on one network with PROMOTE_NETWORKS=1", async () => {
    const { env } = registry({ INTERNAL_HOSTS: "*.corp.internal", PROMOTE_NETWORKS: "1", BEHIND_CLOUDFLARE: "false" });
    const up = await send(env, "POST", "/v1/versions", { as: install(), body });
    assert.equal(up.status, 201, up.text);
    assert.equal(up.body.status, "candidate", up.text);
    await report(env, install(), up.body.hash, "ok");
    const r = await report(env, install(), up.body.hash, "ok", "198.51.100.8");
    assert.equal(r.status, 200, r.text);
    const s = await send(env, "GET", "/v1/sites/corp-internal");
    assert.match(s.text, /"status":"live"/, s.text);
  });

  test("with the default PROMOTE_NETWORKS a single network keeps it a candidate; a trusted header tells networks apart", async () => {
    const one = registry({ INTERNAL_HOSTS: "*.corp.internal", BEHIND_CLOUDFLARE: "false" }).env;
    const a = await send(one, "POST", "/v1/versions", { as: install(), body });
    await report(one, install(), a.body.hash, "ok", "10.1.0.1");
    await report(one, install(), a.body.hash, "ok", "10.2.0.1");
    assert.match((await send(one, "GET", "/v1/sites/corp-internal")).text, /"status":"candidate"/);

    const two = registry({
      INTERNAL_HOSTS: "*.corp.internal",
      BEHIND_CLOUDFLARE: "false",
      TRUSTED_IP_HEADER: "x-forwarded-for",
    }).env;
    const b = await send(two, "POST", "/v1/versions", { as: install(), body });
    for (const ip of ["10.1.0.1", "10.2.0.1"])
      await send(two, "POST", "/v1/reports", {
        as: install(),
        headers: { "x-forwarded-for": `6.6.6.6, ${ip}` },
        body: { reports: [{ hash: b.body.hash, outcome: "ok" }] },
      });
    assert.match((await send(two, "GET", "/v1/sites/corp-internal")).text, /"status":"live"/);
  });
});
