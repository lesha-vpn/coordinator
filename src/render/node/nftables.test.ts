import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import type { LocalRenderInput, RemoteRenderInput } from './input'
import { renderLocalNft, renderRemoteNft } from './nftables'

const params = { Jc: '4', Jmin: '40', Jmax: '70' }

function localInput(over: Partial<LocalRenderInput> = {}): LocalRenderInput {
  return {
    node: 'main/local',
    identity: {
      role: 'local',
      awgc: { privateKey: 'cpriv', publicKey: 'cpub', listenPort: 51820, protocol: 'awg2' as const, params },
      awgt: { privateKey: 'tpriv', publicKey: 'tpub' },
    },
    remote: { privateKey: 'rpriv', publicKey: 'rpub', presharedKey: 'psk', listenPort: 41000, protocol: 'awg2' as const, params },
    addresses: { client: '203.0.113.10', outer: '203.0.113.11', tunnel: '203.0.113.12' },
    sshPort: 22,
    remoteTunnelAddress: '198.51.100.20',
    clientSubnet: '10.66.0.0/16',
    tunnelSubnet: '10.255.0.0/30',
    tunnelMtu: 1380,
    peers: [],
    geoHome: ['5.0.0.0/8', '31.40.0.0/16', '5.0.0.0/8'],
    forceRemote: ['8.8.8.8/32'],
    ...over,
  }
}

function remoteInput(over: Partial<RemoteRenderInput> = {}): RemoteRenderInput {
  return {
    node: 'main/remote',
    identity: { role: 'remote', awgt: { privateKey: 'rpriv', publicKey: 'rpub', presharedKey: 'psk', listenPort: 41000, protocol: 'awg2' as const, params } },
    localAwgtPublicKey: 'tpub',
    addresses: { outer: '198.51.100.21', tunnel: '198.51.100.20' },
    sshPort: 22,
    localTunnelAddress: '203.0.113.12',
    tunnelSubnet: '10.255.0.0/30',
    tunnelMtu: 1380,
    ...over,
  }
}

function setBlock(out: string, name: string): string {
  const start = out.indexOf(`set ${name} {`)
  return out.slice(start, out.indexOf('\n  }', start))
}

describe('renderLocalNft', () => {
  const out = renderLocalNft(localInput())

  it('replaces the whole ruleset with one inet table', () => {
    expect(out.startsWith('#!/usr/sbin/nft -f\n\nflush ruleset\n')).toBe(true)
    expect(out.match(/^table /gm)).toEqual(['table '])
    expect(out).toContain('table inet vpn {')
  })

  it('restricts input to SSH on outer and AWG on client', () => {
    expect(out).toContain('type filter hook input priority filter; policy drop;')
    expect(out).toContain('ct state established,related accept')
    expect(out).toContain('iifname "lo" accept')
    expect(out).toContain('meta l4proto icmp accept')
    expect(out).toContain('ip daddr 203.0.113.11 tcp dport 22 accept')
    expect(out).toContain('ip daddr 203.0.113.10 udp dport 51820 accept')
    expect(out.match(/dport 22/g)).toHaveLength(1)
    expect(out.match(/udp dport/g)).toHaveLength(1)
  })

  it('opens the configured non-22 SSH port instead of 22', () => {
    const custom = renderLocalNft(localInput({ sshPort: 2222 }))
    expect(custom).toContain('ip daddr 203.0.113.11 tcp dport 2222 accept')
    expect(custom).not.toContain('tcp dport 22 ')
  })

  it('renders geo sets with deduplicated elements', () => {
    const geo = setBlock(out, 'geo_home')
    expect(geo).toContain('type ipv4_addr')
    expect(geo).toContain('flags interval')
    expect(geo).toContain('auto-merge')
    expect(geo).toContain('5.0.0.0/8, 31.40.0.0/16')
    expect(geo.match(/5\.0\.0\.0\/8/g)).toHaveLength(1)
    expect(setBlock(out, 'force_remote')).toContain('8.8.8.8/32')
    expect(setBlock(out, 'private')).toContain('100.64.0.0/10')
  })

  it('omits elements of empty sets', () => {
    const empty = renderLocalNft(localInput({ geoHome: [], forceRemote: [] }))
    expect(setBlock(empty, 'geo_home')).not.toContain('elements')
    expect(setBlock(empty, 'force_remote')).not.toContain('elements')
  })

  it('marks foreign traffic in mangle prerouting in the right order', () => {
    expect(out).toContain('type filter hook prerouting priority mangle; policy accept;')
    const rules = [
      'iifname "awgc" ip daddr @force_remote meta mark set 0x52 return',
      'iifname "awgc" ip daddr @geo_home return',
      'iifname "awgc" ip daddr @private return',
      'iifname "awgc" meta mark set 0x52\n',
    ]
    const idx = rules.map(r => out.indexOf(r))
    expect(idx.every(i => i > 0)).toBe(true)
    expect([...idx].sort((a, b) => a - b)).toEqual(idx)
  })

  it('forward: fail-closed and client isolation before any accept', () => {
    const fwd = out.slice(out.indexOf('chain forward'))
    const failClosed = fwd.indexOf('meta mark 0x52 oifname != "awgt" drop')
    const isolate = fwd.indexOf('iifname "awgc" oifname "awgc" drop')
    const firstAccept = fwd.indexOf('accept')
    expect(failClosed).toBeGreaterThan(0)
    expect(isolate).toBeGreaterThan(0)
    expect(failClosed).toBeLessThan(firstAccept)
    expect(isolate).toBeLessThan(firstAccept)
    expect(fwd).toContain('policy drop;')
    expect(fwd).toContain('meta nfproto ipv6 drop')
    expect(fwd).toContain('tcp flags syn tcp option maxseg size set rt mtu')
    expect(fwd).toContain('iifname "awgc" accept')
  })

  it('NATs client traffic to tunnel address or outer', () => {
    expect(out).toContain('oifname "awgt" ip saddr 10.66.0.0/16 snat ip to 10.255.0.1')
    expect(out).toContain('oifname != { "awgt", "awgc" } ip saddr 10.66.0.0/16 snat ip to 203.0.113.11')
  })

  it('is deterministic', () => {
    expect(renderLocalNft(localInput())).toBe(out)
  })
})

describe('renderLocalNft with the SOCKS5 proxy (R-L8)', () => {
  const socks = { port: 1080, users: [{ login: 'alice', password: 'P' }], dns: ['1.1.1.1'] }
  const out = renderLocalNft(localInput({ socks }))
  const chainOf = (name: string) => out.slice(out.indexOf(`chain ${name} {`), out.indexOf('\n  }', out.indexOf(`chain ${name} {`)))

  it('without it nothing changes', () => {
    const plain = renderLocalNft(localInput())
    expect(plain).not.toContain('vpn-socks')
    expect(plain).not.toContain('tcp dport 1080')
  })

  it('opens the proxy port on LOCAL.client only', () => {
    expect(out).toContain('ip daddr 203.0.113.10 tcp dport 1080 accept')
    expect(out.match(/tcp dport 1080/g)).toHaveLength(1)
  })

  it('routes the proxy\'s own connections like client traffic, in the same order', () => {
    const route = chainOf('socks_route')
    expect(route).toContain('type route hook output priority mangle; policy accept;')
    const own = 'meta skuid "vpn-socks" ct direction original'
    const rules = [
      `${own} ip daddr @force_remote meta mark set 0x52 return`,
      `${own} ip daddr @geo_home return`,
      `${own} ip daddr @private return`,
      `${own} meta mark set 0x52\n`,
    ]
    const idx = rules.map(r => (route + '\n').indexOf(r))
    expect(idx.every(i => i > 0)).toBe(true)
    expect([...idx].sort((a, b) => a - b)).toEqual(idx)
  })

  it('keeps the proxy off the node, the private ranges and IPv6', () => {
    const own = 'meta skuid "vpn-socks" ct direction original'
    const filter = chainOf('socks_out')
    expect(filter).toContain('type filter hook output priority filter; policy accept;')
    // Every rule names the proxy user: packets without a socket fall through untouched.
    const rules = filter.split('\n').map(l => l.trim()).filter(l => /(accept|drop|reject)$/.test(l))
    expect(rules).toEqual([
      `${own} meta nfproto ipv6 reject`,
      `${own} ip daddr @private reject`,
      `${own} ip daddr { 203.0.113.10, 203.0.113.11, 203.0.113.12 } reject`,
    ])
  })

  it('fail-closed and MSS clamp in postrouting, where oifname is the rerouted device', () => {
    const post = chainOf('socks_post')
    expect(post).toContain('type filter hook postrouting priority filter; policy accept;')
    expect(post).toContain('meta skuid "vpn-socks" ct direction original meta mark 0x52 oifname != "awgt" drop')
    expect(post).toContain('meta skuid "vpn-socks" ct direction original oifname "awgt" tcp flags syn tcp option maxseg size set rt mtu')
    expect(chainOf('socks_out')).not.toContain('oifname')
  })

  it('NATs the proxy\'s traffic to the tunnel address or outer', () => {
    expect(out).toContain('oifname "awgt" meta skuid "vpn-socks" snat ip to 10.255.0.1')
    expect(out).toContain('oifname != { "awgt", "awgc" } meta skuid "vpn-socks" snat ip to 203.0.113.11')
  })
})

describe('renderRemoteNft', () => {
  const out = renderRemoteNft(remoteInput())

  it('allows AWG only from LOCAL.tunnel to REMOTE.tunnel', () => {
    expect(out.startsWith('#!/usr/sbin/nft -f\n\nflush ruleset\n')).toBe(true)
    expect(out).toContain('ip saddr 203.0.113.12 ip daddr 198.51.100.20 udp dport 41000 accept')
    expect(out).toContain('ip daddr 198.51.100.21 tcp dport 22 accept')
    expect(out).not.toContain('set geo_home')
    expect(out).not.toContain('awgc')
  })

  it('opens the configured non-22 SSH port instead of 22', () => {
    const custom = renderRemoteNft(remoteInput({ sshPort: 2200 }))
    expect(custom).toContain('ip daddr 198.51.100.21 tcp dport 2200 accept')
    expect(custom).not.toContain('tcp dport 22 ')
  })

  it('forwards and NATs tunnel traffic', () => {
    expect(out).toContain('iifname "awgt" accept')
    expect(out).toContain('meta nfproto ipv6 drop')
    expect(out).toContain('tcp flags syn tcp option maxseg size set rt mtu')
    expect(out).toContain('oifname != "awgt" ip saddr 10.255.0.0/30 snat ip to 198.51.100.21')
  })

  it('is deterministic', () => {
    expect(renderRemoteNft(remoteInput())).toBe(out)
  })
})

// Syntax check with the real parser when available (needs CAP_NET_ADMIN for -c).
const nftUsable = (() => {
  try {
    const dir = mkdtempSync(join(tmpdir(), 'nftprobe-'))
    const f = join(dir, 'p.nft')
    writeFileSync(f, 'table inet probe {\n}\n')
    return spawnSync('nft', ['-c', '-f', f]).status === 0
  } catch { return false }
})()

describe.skipIf(!nftUsable)('nft -c', () => {
  const check = (text: string) => {
    const f = join(mkdtempSync(join(tmpdir(), 'nftcheck-')), 'nftables.conf')
    writeFileSync(f, text)
    execFileSync('nft', ['-c', '-f', f], { stdio: 'pipe' })
  }
  it('accepts the LOCAL ruleset', () => check(renderLocalNft(localInput())))
  it('accepts the LOCAL ruleset with empty sets', () => check(renderLocalNft(localInput({ geoHome: [], forceRemote: [] }))))
  it('accepts the REMOTE ruleset', () => check(renderRemoteNft(remoteInput())))
  // nft resolves user names at load time; the CI host has no vpn-socks user, root stands in.
  it('accepts the LOCAL ruleset with the SOCKS5 proxy', () => check(
    renderLocalNft(localInput({ socks: { port: 1080, users: [], dns: ['1.1.1.1'] } })).replaceAll('"vpn-socks"', '"root"'),
  ))
})
