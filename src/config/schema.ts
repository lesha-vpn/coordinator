import { z } from 'zod'
import { cidrToRange } from '../geo/cidr'

// Declarative coordinator config (spec section 5). Only addresses, credentials and
// policy live here; keys, ports, obfuscation params and internal addresses are node
// identity and live in the DB (R-C4).

const ipv4 = z.string().regex(
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/,
  'expected an IPv4 address'
)

const cidr = z.string().regex(
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/,
  'expected an IPv4 CIDR'
)

// Internal subnets need at least hosts .1 and .2 (gateway/LOCAL and the first client/REMOTE):
// a /31 or /32 passed the schema and then failed every render cycle.
const internalSubnet = cidr.refine(value => Number(value.split('/')[1]) <= 30, 'prefix must be /30 or shorter')

// "203.0.113.10" or "203.0.113.10/24"; the prefix is informational only.
const hostAddress = z.string().regex(
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(\/(3[0-2]|[12]?\d))?$/,
  'expected an IPv4 address, optionally with /prefix'
).transform(value => value.split('/')[0])

export const protocolNames = ['awg2', 'awg3'] as const
export const protocolName = z.enum(protocolNames)
export type ProtocolName = z.infer<typeof protocolName>

const ssh = z.object({
  user: z.string().min(1).default('root'),
  password: z.string().optional(),
  port: z.number().int().min(1).max(65535).default(22),
})

const countryCode = z.string().regex(/^[A-Z]{2}$/, 'expected ISO 3166-1 alpha-2 country code')

const localNode = z.object({
  country: countryCode,
  ssh,
  addresses: z.object({
    client: hostAddress,
    outer: hostAddress,
    tunnel: hostAddress,
  }),
})

const remoteNode = z.object({
  // Where foreign traffic exits; names the server in the app (Config.serverName). Optional so
  // configs from before it existed still load; without it the site name is shown.
  country: countryCode.optional(),
  ssh,
  addresses: z.object({
    outer: hostAddress,
    tunnel: hostAddress,
  }),
})

const siteName = z.string().regex(/^[a-z0-9-]{1,32}$/, 'site name must match [a-z0-9-]{1,32}')

export const configSchema = z.object({
  telegram: z.object({
    botToken: z.string().min(1),
    // Group and supergroup ids are negative (-100… for supergroups); a positive id is a user's DM,
    // where membership checks would never pass. Deploy 2026-10-13: the id was copied without the minus.
    chatId: z.number().int().negative('expected a group chat id (negative, e.g. -1001234567890); positive ids are users'),
    admins: z.array(z.number().int()).min(1),
    announceOutages: z.boolean().default(true),
  }),
  api: z.object({
    listen: z.string().regex(/^[^:]+:\d+$/, 'expected host:port').default('127.0.0.1:8080'),
    publicUrl: z.string().url(),
  }),
  // Prometheus /metrics on a separate (loopback) listener; off when absent (R-O7).
  metrics: z.object({
    listen: z.string().regex(/^[^:]+:\d+$/, 'expected host:port').default('127.0.0.1:9469'),
  }).optional(),
  clients: z.object({
    subnet: internalSubnet.default('10.66.0.0/16'),
    mtu: z.number().int().min(1200).max(1500).default(1280),
    dns: z.array(ipv4).min(1).default(['1.1.1.1', '8.8.8.8']),
    protocol: protocolName.default('awg3'),
  }).prefault({}),
  tunnel: z.object({
    subnet: internalSubnet.default('10.255.0.0/30'),
    mtu: z.number().int().min(1200).max(1500).default(1380),
    protocol: protocolName.default('awg3'),
  }).prefault({}),
  routing: z.object({
    geoSource: z.literal('dbip-lite').default('dbip-lite'),
    alwaysDirect: z.array(cidr).default([]),
    alwaysRemote: z.array(cidr).default([]),
  }).prefault({}),
  sites: z.array(z.object({
    name: siteName,
    local: localNode,
    remote: remoteNode,
  })).min(1).refine(
    sites => new Set(sites.map(site => site.name)).size === sites.length,
    'site names must be unique'
  ),
}).superRefine((config, ctx) => {
  // Overlapping subnets would hand clients the tunnel's addresses (10.255.0.0/16 for clients
  // allocates 10.255.0.2, REMOTE's awgt address) and break routing silently.
  const [cs, ce] = cidrToRange(config.clients.subnet)
  const [ts, te] = cidrToRange(config.tunnel.subnet)
  if(cs <= te && ts <= ce) {
    ctx.addIssue({ code: 'custom', path: ['tunnel', 'subnet'], message: `overlaps clients.subnet ${config.clients.subnet}` })
  }
})

export type CoordinatorConfig = z.infer<typeof configSchema>
export type SiteConfig = CoordinatorConfig['sites'][number]
export type SshConfig = z.infer<typeof ssh>
