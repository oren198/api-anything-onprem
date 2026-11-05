# Internal deployment

Running api-anything inside a company network, with a private registry, for internal sites. Nothing
here changes a default install: with none of these settings set, every shared spec still has to go to a
public https host, and the client uses the public registry.

## Client

| Setting | What it does |
| --- | --- |
| `API_ANYTHING_REGISTRY` | the registry's base URL; https (http only to localhost). |
| settings.json `registry` | the same, kept in `$API_ANYTHING_HOME/settings.json`, used when the env var is unset. A fork that should never reach the public registry sets it here (or changes `REGISTRY_API` in `src/registry-api.ts`). |
| `API_ANYTHING_INTERNAL_HOSTS` | comma-separated host globs and CIDRs that shared specs may reach: `*.corp.example,app.corp.internal,10.0.0.0/8,fd00::/8`. |
| `NODE_EXTRA_CA_CERTS` | a PEM file with the company CA, for Node's own requests (tier 1 and the registry). |

The rules of `API_ANYTHING_INTERNAL_HOSTS` (`src/internal.ts`):

- `*.corp.example` matches every host under corp.example, not corp.example itself; any other entry
  matches exactly. A listed host may be one without a public suffix (`app.corp.internal`).
- A listed host may resolve to a private LAN address (10/8, 172.16/12, 192.168/16, 100.64/10,
  fc00::/7), never to loopback, link-local (cloud metadata, 169.254.169.254) or multicast.
- A listed CIDR admits any host that resolves inside it, and an IP literal inside it. This is broader:
  use it only for ranges every shared spec may reach.
- Still https only: a shared spec is never sent over plain http, internal or not.
- The same rules apply to every redirect hop of a shared spec's call.
- If `API_ANYTHING_INTERNAL_HOSTS` is set and no registry is, the client warns on stderr that it is
  using the public registry.

`api-anything setup` and `mcp --print-config` write `API_ANYTHING_HOME`, `API_ANYTHING_BROWSER`,
`API_ANYTHING_REGISTRY`, `API_ANYTHING_INTERNAL_HOSTS` and `NODE_EXTRA_CA_CERTS` into each agent's MCP
config, so an agent started from a menu uses the same registry and allowlist as your shell.

### The company CA in Chrome

Learning drives Chrome, which does not read `NODE_EXTRA_CA_CERTS`. Add the CA to the system trust that
Chrome uses: on Linux the NSS database (`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n corp -i ca.pem`),
on macOS the System keychain, on Windows the machine's Trusted Root store (or by policy).

## Registry

The registry (`registry/`) is a Cloudflare Worker over D1. Its settings are Worker vars (or `.dev.vars`
locally):

| Var | What it does |
| --- | --- |
| `SALT`, `ADMIN_TOKEN` | required secrets. |
| `INTERNAL_HOSTS` | the host globs (and CIDRs, for IP-literal hosts) whose sites it accepts; same syntax as the client's. Unset: only public hosts. |
| `BEHIND_CLOUDFLARE` | `false` when not behind Cloudflare: `cf-connecting-ip` and `request.cf` (the ASN) are then a client's to forge, and are ignored. |
| `TRUSTED_IP_HEADER` | a header your own proxy sets with the client address, e.g. `x-forwarded-for` or `x-real-ip`. |
| `TRUSTED_PROXY_HOPS` | which address of that header: 1 (default) the rightmost, the one your proxy appended; n for n proxies in a row. Addresses a client prepends are never read. |
| `PROMOTE_NETWORKS`, `DEGRADE_MIN_NETWORKS` | how many distinct networks (/24 or IPv6 /32 of the client address; the ASN behind Cloudflare) promote or degrade a version. Defaults 2 and 3. |

A network is a /24. In a company where every install reaches the registry from one /24, or through one
NAT, or with no trusted header at all (every install is then the same unknown network), versions never
go live with the defaults. Either set `TRUSTED_IP_HEADER` so installs on different subnets count
apart, or count installs only: `PROMOTE_NETWORKS=1` and `DEGRADE_MIN_NETWORKS=1` (and maybe
`CLAIM_KEYS` lower). Promotion then still needs `PROMOTE_KEYS` (default 2) installs other than the
uploader.

### Running it off Cloudflare

Locally, with no Cloudflare account:

```
cd registry
printf 'SALT=...\nADMIN_TOKEN=...\nINTERNAL_HOSTS=*.corp.example\nBEHIND_CLOUDFLARE=false\nPROMOTE_NETWORKS=1\n' > .dev.vars
npx wrangler d1 migrations apply api-anything-registry --local
npx wrangler dev --local --ip 0.0.0.0 --port 8787
```

Caveats: `wrangler dev` is a development server; its D1 is a SQLite file under `registry/.wrangler/state`
(back it up). The crons do not run on their own there; call
`curl "http://127.0.0.1:8787/cdn-cgi/handler/scheduled?cron=*+*+*+*+*"` (every minute) and with
`cron=17+3+*+*+*` (daily) from a scheduler. Put a TLS proxy in front (the client needs https unless it
runs on the same machine) and have it set `TRUSTED_IP_HEADER`. For production, `workerd` (the open-source
runtime) with a config that binds D1 is the closer fit; this repository ships no such config and it is
not tested here. To seed the bundled public sites: `npx tsx registry/seed.ts <registry url>`, with the
admin token in `~/.api-anything-admin-token`; an internal catalog may not want them.
