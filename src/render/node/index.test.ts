import { describe, expect, it, vi } from 'vitest'
import { localInput, remoteInput } from './testFixtures'
import { desiredHash, renderLocal, renderRemote } from './index'

// Keep these tests about composition; nftables has its own tests.
vi.mock('./nftables', () => ({
  renderLocalNft: () => 'local-nft\n',
  renderRemoteNft: () => 'remote-nft\n',
}))

describe('renderLocal', () => {
  it('produces all LOCAL files with modes', () => {
    const files = renderLocal(localInput)
    expect(files.map(f => [f.path, f.mode])).toEqual([
      ['/etc/amnezia/amneziawg/awgc.conf', 0o600],
      ['/etc/amnezia/amneziawg/awgt.conf', 0o600],
      ['/etc/nftables.conf', 0o644],
      ['/etc/sysctl.d/90-vpn-node.conf', 0o644],
      ['/etc/vpn-node/routing.sh', 0o755],
      ['/etc/systemd/system/vpn-routing.service', 0o644],
    ])
    expect(files[2].content).toBe('local-nft\n')
  })
})

describe('renderLocal with the SOCKS5 proxy (R-L8)', () => {
  const socks = { port: 1080, users: [{ login: 'alice', password: 'Abc123' }, { login: 'tg42', password: 'Xyz789' }], dns: ['1.1.1.1', '8.8.8.8'] }
  const files = renderLocal({ ...localInput, socks })
  const file = (p: string) => files.find(f => f.path === p)!

  it('adds gost conf, users and unit; users readable by the group only', () => {
    expect(files.slice(6).map(f => [f.path, f.mode])).toEqual([
      ['/etc/vpn-node/socks/gost.yaml', 0o640],
      ['/etc/vpn-node/socks/users', 0o640],
      ['/etc/systemd/system/vpn-socks.service', 0o644],
    ])
    expect(file('/etc/vpn-node/socks/users').content).toBe('alice Abc123\ntg42 Xyz789\n')
  })

  it('gost listens on LOCAL.client with auth from the reloaded file and resolves via clients.dns', () => {
    const conf = file('/etc/vpn-node/socks/gost.yaml').content
    expect(conf).toContain('addr: "1.1.1.10:1080"')
    expect(conf).toContain('type: socks5')
    expect(conf).toContain('auther: users')
    expect(conf).toContain('path: "/etc/vpn-node/socks/users"')
    expect(conf).toContain('reload: 10s')
    expect(conf).toContain('resolver: dns')
    expect(conf).toContain('- addr: "udp://1.1.1.1:53"')
    expect(conf).toContain('- addr: "udp://8.8.8.8:53"')
  })

  it('runs gost as vpn-socks', () => {
    const unit = file('/etc/systemd/system/vpn-socks.service').content
    expect(unit).toContain('User=vpn-socks')
    expect(unit).toContain('ExecStart=/usr/local/bin/gost -C /etc/vpn-node/socks/gost.yaml')
    expect(unit).toContain('After=network-online.target vpn-routing.service')
  })

  it('refuses logins or passwords that could break the users file', () => {
    expect(() => renderLocal({ ...localInput, socks: { ...socks, users: [{ login: 'a b', password: 'x' }] } })).toThrow()
    expect(() => renderLocal({ ...localInput, socks: { ...socks, users: [{ login: 'a', password: 'x\nb c' }] } })).toThrow()
  })
})

describe('renderRemote', () => {
  it('has no routing script or unit', () => {
    const files = renderRemote(remoteInput)
    expect(files.map(f => f.path)).toEqual([
      '/etc/amnezia/amneziawg/awgt.conf', '/etc/nftables.conf', '/etc/sysctl.d/90-vpn-node.conf',
    ])
    expect(files[1].content).toBe('remote-nft\n')
  })
})

describe('desiredHash', () => {
  const files = renderLocal(localInput)

  it('is sha256 hex and independent of file order', () => {
    const h = desiredHash(files, 'v1')
    expect(h).toMatch(/^[0-9a-f]{64}$/)
    expect(desiredHash([...files].reverse(), 'v1')).toBe(h)
  })

  it('is stable across renders, including peer order', () => {
    const shuffled = { ...localInput, peers: [...localInput.peers].reverse() }
    expect(desiredHash(renderLocal(shuffled), 'v1')).toBe(desiredHash(files, 'v1'))
  })

  it('changes with content, mode, path and extra', () => {
    const h = desiredHash(files, 'v1')
    expect(desiredHash(files, 'v2')).not.toBe(h)
    expect(desiredHash(files.map((f, i) => i === 0 ? { ...f, mode: 0o644 } : f), 'v1')).not.toBe(h)
    expect(desiredHash(files.map((f, i) => i === 0 ? { ...f, content: f.content + '#' } : f), 'v1')).not.toBe(h)
    expect(desiredHash(files.map((f, i) => i === 0 ? { ...f, path: f.path + 'x' } : f), 'v1')).not.toBe(h)
    expect(desiredHash(renderLocal({ ...localInput, peers: localInput.peers.slice(1) }), 'v1')).not.toBe(h)
  })

  it('does not collide on shifted field boundaries', () => {
    const a = [{ path: '/a', mode: 0o600, content: 'bc' }]
    const b = [{ path: '/ab', mode: 0o600, content: 'c' }]
    expect(desiredHash(a, '')).not.toBe(desiredHash(b, ''))
  })
})
