/**
 * Internal hosts an internal deployment allows (docs/INTERNAL.md): `API_ANYTHING_INTERNAL_HOSTS` on the
 * client, `INTERNAL_HOSTS` on the registry, a comma-separated list of host globs (`*.corp.example`,
 * `app.corp.internal`) and CIDRs (`10.0.0.0/8`, `fd00::/8`). Empty, the default: nothing changes, and
 * every shared spec must go to a public https host. Pure (no file or network access), so the registry
 * service shares it.
 */
import { isIP, isIPv4 } from "node:net";

export interface InternalHosts {
  /** lower-case globs: `*.x.y` matches any host under x.y (not x.y itself); anything else matches exactly */
  globs: string[];
  cidrs: { v6: boolean; bits: bigint; prefix: number }[];
}

export const NO_INTERNAL: InternalHosts = { globs: [], cidrs: [] };

/** An IP as a 32- or 128-bit number; undefined for anything else. */
function ipBits(ip: string): { v6: boolean; bits: bigint } | undefined {
  const h = ip.replace(/^\[|\]$/g, "").toLowerCase();
  if (isIPv4(h)) return { v6: false, bits: h.split(".").reduce((n, o) => (n << 8n) | BigInt(Number(o)), 0n) };
  if (isIP(h) !== 6) return undefined;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h)?.[1];
  if (mapped) return ipBits(mapped);
  const [head = "", tail] = h.split("::");
  const a = head ? head.split(":") : [];
  const b = tail ? tail.split(":") : [];
  const groups = tail === undefined ? a : [...a, ...Array(8 - a.length - b.length).fill("0"), ...b];
  return { v6: true, bits: groups.reduce((n, g) => (n << 16n) | BigInt(Number.parseInt(g || "0", 16)), 0n) };
}

/** Parses the list; an entry that is neither a host nor a CIDR throws, so a typo is not a silent no. */
export function parseInternalHosts(list: string | undefined): InternalHosts {
  const out: InternalHosts = { globs: [], cidrs: [] };
  for (const raw of (list ?? "").split(",")) {
    const e = raw.trim().toLowerCase();
    if (!e) continue;
    const cidr = /^([^/]+)\/(\d{1,3})$/.exec(e);
    if (cidr) {
      const ip = ipBits(cidr[1]!);
      const prefix = Number(cidr[2]);
      if (!ip || prefix > (ip.v6 ? 128 : 32)) throw new Error(`internal hosts: ${raw.trim()} is no CIDR`);
      out.cidrs.push({ ...ip, prefix });
    } else if (/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(e) || ipBits(e)) {
      out.globs.push(e);
    } else throw new Error(`internal hosts: ${raw.trim()} is neither a host, a *.host glob nor a CIDR`);
  }
  return out;
}

/** Whether `host` matches a glob of the list. */
export function hostInternal(host: string, list: InternalHosts): boolean {
  const h = host
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[|\]$/g, "");
  return list.globs.some((g) => (g.startsWith("*.") ? h.endsWith(g.slice(1)) && h.length > g.length - 1 : h === g));
}

/** Whether `ip` is inside a CIDR of the list. */
export function ipInternal(ip: string, list: InternalHosts): boolean {
  const a = ipBits(ip);
  if (!a) return false;
  return list.cidrs.some((c) => {
    if (c.v6 !== a.v6) return false;
    const shift = BigInt((c.v6 ? 128 : 32) - c.prefix);
    return a.bits >> shift === c.bits >> shift;
  });
}

let configured: InternalHosts | undefined;

/** Sets the list for this process (the registry does, from its env, on each request); undefined: back to the env. */
export function setInternalHosts(list: string | undefined): void {
  configured = list === undefined ? undefined : parseInternalHosts(list);
}

/** The list in force: what `setInternalHosts` set, else `API_ANYTHING_INTERNAL_HOSTS`, read on each call. */
export function internalHosts(): InternalHosts {
  if (configured) return configured;
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  return parseInternalHosts(env?.API_ANYTHING_INTERNAL_HOSTS);
}
