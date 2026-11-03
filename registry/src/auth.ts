/** Who sent a request: the install's key from its signature (src/registry-api.ts), and its network, hashed. */
import { signingText } from "../../src/registry-api.js";

const SKEW_MS = 5 * 60_000;

export async function sha256Hex(data: string | Uint8Array<ArrayBuffer>): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromBase64url(s: string): Uint8Array<ArrayBuffer> | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return undefined;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

export type Signer = { key: string } | { error: string } | undefined;

interface SignatureHeaders {
  key: string;
  ts: string;
  sig: string;
}

/**
 * The signature headers, checked for presence and clock skew only: cheap enough to run before the body
 * is read. Undefined when the request carries none of them.
 */
export function signatureHeaders(headers: Headers, now = Date.now()): SignatureHeaders | { error: string } | undefined {
  const key = headers.get("x-aa-key");
  const ts = headers.get("x-aa-ts");
  const sig = headers.get("x-aa-sig");
  if (!key && !ts && !sig) return undefined;
  if (!key || !ts || !sig) return { error: "a signed request needs x-aa-key, x-aa-ts and x-aa-sig" };
  if (!/^\d{1,16}$/.test(ts) || Math.abs(now - Number(ts)) > SKEW_MS)
    return { error: "x-aa-ts is more than 5 minutes off the server's clock" };
  return { key, ts, sig };
}

/**
 * The key that signed the request, an error when its signature does not hold, or undefined when it is
 * not signed. The signed path is exactly the pathname with its query, so the signature binds the query too.
 */
export async function signer(request: Request, body: Uint8Array<ArrayBuffer>, now = Date.now()): Promise<Signer> {
  const h = signatureHeaders(request.headers, now);
  if (!h || "error" in h) return h;
  const raw = fromBase64url(h.key);
  const signature = fromBase64url(h.sig);
  if (raw?.length !== 32) return { error: "x-aa-key is not a 32-byte Ed25519 public key, base64url" };
  if (signature?.length !== 64) return { error: "x-aa-sig is not a 64-byte Ed25519 signature, base64url" };
  const url = new URL(request.url);
  const text = signingText(request.method, url.pathname + url.search, h.ts, await sha256Hex(body));
  const publicKey = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  if (await crypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, new TextEncoder().encode(text)))
    return { key: h.key };
  return { error: "the signature does not match the request" };
}

/**
 * An IP's /24 (v4) or /32 (v6); a v4-mapped v6 address is read as v4. A /32 is an ISP's allocation: one
 * subscriber gets a /48 or more, so a /48 lets one host rotate through 65536 networks.
 */
export function prefixOf(ip: string): string {
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(ip);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}`;
  if (!ip.includes(":")) return "unknown";
  const [head = "", tail] = ip.toLowerCase().split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = tail === undefined ? h : [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t];
  return groups
    .slice(0, 2)
    .map((g) => g.replace(/^0+(?=.)/, ""))
    .join(":");
}

/** Where the registry reads a request's IP and ASN from (docs/INTERNAL.md "Registry"). */
export interface NetworkSource {
  /** a header the deployment's own proxy sets, e.g. x-forwarded-for; unset: cf-connecting-ip */
  trustedIpHeader?: string;
  /** which address of a comma-separated header: 1 (default) the rightmost, the hop the trusted proxy saw; n: the nth from the right */
  trustedHops?: number;
  /** false: not behind Cloudflare, so cf-connecting-ip and request.cf are a client's to forge and are ignored */
  cloudflare?: boolean;
}

/** The NetworkSource of a Worker env: TRUSTED_IP_HEADER, TRUSTED_PROXY_HOPS, BEHIND_CLOUDFLARE ("false" or "0" turns it off). */
export function networkSource(env: Record<string, unknown>): NetworkSource {
  const header = typeof env.TRUSTED_IP_HEADER === "string" ? env.TRUSTED_IP_HEADER.trim().toLowerCase() : "";
  const hops = Number(env.TRUSTED_PROXY_HOPS);
  const cf = typeof env.BEHIND_CLOUDFLARE === "string" ? !/^(false|0|no)$/i.test(env.BEHIND_CLOUDFLARE.trim()) : true;
  return {
    ...(header ? { trustedIpHeader: header } : {}),
    ...(Number.isInteger(hops) && hops >= 1 ? { trustedHops: hops } : {}),
    cloudflare: cf,
  };
}

/**
 * The client IP by `source`: the trusted header's nth address from the right (a client can prepend any
 * addresses it likes to x-forwarded-for, but not the ones the proxies append), else cf-connecting-ip
 * behind Cloudflare, else "" (one unknown network).
 */
export function clientIp(headers: Headers, source: NetworkSource = {}): string {
  if (source.trustedIpHeader) {
    const hops = (headers.get(source.trustedIpHeader) ?? "")
      .split(",")
      .map((h) => h.trim())
      .filter(Boolean);
    return hops[hops.length - (source.trustedHops ?? 1)] ?? "";
  }
  return source.cloudflare === false ? "" : (headers.get("cf-connecting-ip") ?? "");
}

/**
 * The request's networks, hashed with the salt: `network` (its ASN, else its IP prefix) is what promotion
 * counts; `prefix` (always the IP prefix) is what rate limits count, since one ASN holds a whole ISP.
 */
export async function networksOf(
  request: Request,
  salt: string,
  source: NetworkSource = {},
): Promise<{ network: string; prefix: string }> {
  const asn = source.cloudflare === false ? undefined : (request as Request & { cf?: { asn?: number } }).cf?.asn;
  const ip = `ip:${prefixOf(clientIp(request.headers, source))}`;
  const hash = async (s: string) => (await sha256Hex(`${salt}\n${s}`)).slice(0, 32);
  const prefix = await hash(ip);
  return { network: asn ? await hash(`asn:${asn}`) : prefix, prefix };
}
