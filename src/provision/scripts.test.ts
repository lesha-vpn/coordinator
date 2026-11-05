import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type { RenderedFile } from '../types'
import { NODE_PATHS } from '../render/node/input'
import {
  applyCommand, applyScript, bootstrapScript, buildApplyBundle, disablePasswordScript,
  GOST, installKeyScript, readMarkerCommand, renderMetaEnv, retireScript, shellQuote, type ApplyMeta,
} from './scripts'

function bashSyntaxOk(script: string): void {
  const r = spawnSync('bash', ['-n'], { input: script })
  expect(r.stderr.toString()).toBe('')
  expect(r.status).toBe(0)
}

describe('script syntax', () => {
  it('every generated script passes bash -n', () => {
    bashSyntaxOk(bootstrapScript())
    bashSyntaxOk(installKeyScript('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc+/= vpn-coordinator', '/root'))
    bashSyntaxOk(disablePasswordScript())
    bashSyntaxOk(applyScript())
    bashSyntaxOk(readMarkerCommand())
    bashSyntaxOk(applyCommand())
    bashSyntaxOk(retireScript(['203.0.113.10', '203.0.113.11']))
  })

  it('bootstrap carries the runbook error strings', () => {
    const s = bootstrapScript()
    expect(s).toContain("'unsupported os'")
    expect(s).toContain("'amneziawg module build failed'")
    expect(s).toContain('REBOOT_REQUIRED')
    expect(s).toContain('ppa:amnezia/ppa')
    expect(s).toContain('Unattended-Upgrade::Automatic-Reboot-Time "04:00"')
  })

  it('stdin-fed scripts are wrapped in main() and end with the call', () => {
    for(const s of [bootstrapScript(), installKeyScript('ssh-ed25519 AAAAkey+/= c', '/root'), disablePasswordScript()]) {
      expect(s).toMatch(/^#!\/bin\/bash\n/)
      expect(s).toContain('\nmain() {\n')
      expect(s.trimEnd().split('\n').at(-1)).toBe('main "$@"')
    }
  })

  it('bootstrap keeps stdin away from apt/dkms and reports the tools version', () => {
    const s = bootstrapScript()
    expect(s).toMatch(/"\$@" <\/dev\/null \|\| rc=\$\?\n/)
    expect(s).toContain('add-apt-repository -y ppa:amnezia/ppa </dev/null')
    expect(s).toContain('dkms autoinstall </dev/null')
    expect(s).toContain('awg --version')
    expect(s).toContain("dpkg-query -W -f='${Version}' amneziawg-tools")
    expect(s).toContain('echo "BOOTSTRAP_OK amneziawg-tools=${tools_version:-unknown}"')
  })

  it('bootstrap freezes the kernel before upgrading and never lets apt-get exit 100', () => {
    const s = bootstrapScript()
    expect(s.indexOf('apt-mark hold')).toBeGreaterThan(-1)
    expect(s.indexOf('apt-mark hold')).toBeLessThan(s.indexOf('apt_get full-upgrade'))
    expect(s).not.toContain('linux-headers-$flavour')
    // apt-get's own failure code is 100, the reboot-required code; a failing apt_get must not reboot the node.
    const fn = s.slice(s.indexOf('apt_get() {'), s.indexOf('\n}\n', s.indexOf('apt_get() {')) + 3)
    const r = spawnSync('bash', ['-c', `set -euo pipefail\napt-get() { return 100; }\n${fn}\nmain() { apt_get install x; }\nmain`])
    expect(r.status).toBe(1)
    expect(r.stderr.toString()).toContain('apt-get install failed (exit 100)')
  })

  it('a stdin-reading child cannot swallow the rest of a main()-wrapped script', () => {
    // `cat` stands in for a dpkg maintainer script that drains stdin.
    const r = spawnSync('bash', ['-s'], { input: '#!/bin/bash\nset -euo pipefail\nmain() {\ncat >/dev/null\necho DONE\n}\n\nmain "$@"\n' })
    expect(r.stdout.toString()).toBe('DONE\n')
  })

  it('installKeyScript rejects multi-line keys', () => {
    expect(() => installKeyScript('ssh-ed25519 AAAA\nrm -rf /', '/root')).toThrow()
  })
})

describe('installKeyScript', () => {
  it('is idempotent and sets perms', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'home-'))
    try {
      fs.mkdirSync(path.join(home, '.ssh'))
      fs.writeFileSync(path.join(home, '.ssh/authorized_keys'), 'ssh-rsa AAAAold other')
      const script = installKeyScript('ssh-ed25519 AAAAkey+/= coord', home)
      execFileSync('bash', ['-c', script])
      execFileSync('bash', ['-c', installKeyScript('ssh-ed25519 AAAAkey+/= renamed', home)])
      const ak = fs.readFileSync(path.join(home, '.ssh/authorized_keys'), 'utf8')
      expect(ak).toBe('ssh-rsa AAAAold other\nssh-ed25519 AAAAkey+/= coord\n')
      expect(fs.statSync(path.join(home, '.ssh')).mode & 0o777).toBe(0o700)
      expect(fs.statSync(path.join(home, '.ssh/authorized_keys')).mode & 0o777).toBe(0o600)
    } finally {
      fs.rmSync(home, { recursive: true, force: true })
    }
  })
})

describe('meta.env escaping', () => {
  it('round-trips hostile values through bash', () => {
    const nasty = `it's "$(rm -rf /)" \`x\` $HOME \\ \n done`
    expect(execFileSync('bash', ['-c', `printf %s ${shellQuote(nasty)}`]).toString()).toBe(nasty)
    const env = renderMetaEnv({
      node: nasty, role: 'local', hash: 'abc', coordinatorVersion: "2.0'1",
      addresses: ['10.0.0.1', '10.0.0.2'], interfaces: ['awgc', 'awgt'],
    })
    const out = execFileSync('bash', ['-c', `${env}\nprintf '%s|' "$NODE" "$ROLE" "$COORDINATOR_VERSION" "$ADDRESSES" "$INTERFACES"\nprintf '{%s}' "$MARKER_FIELDS"`]).toString()
    const [vars, json] = [out.slice(0, out.lastIndexOf('|') + 1), out.slice(out.lastIndexOf('|') + 1)]
    expect(vars).toBe(`${nasty}|local|2.0'1|10.0.0.1 10.0.0.2|awgc awgt|`)
    expect(JSON.parse(json)).toEqual({ node: nasty, role: 'local', appliedHash: 'abc', coordinatorVersion: "2.0'1" })
  })

  it('rejects bad addresses and interfaces', () => {
    const base: ApplyMeta = { node: 'n', role: 'remote', hash: 'h', coordinatorVersion: 'v', addresses: [], interfaces: [] }
    expect(() => renderMetaEnv({ ...base, addresses: ['1.2.3.4; reboot'] })).toThrow()
    expect(() => renderMetaEnv({ ...base, interfaces: ['awg t'] })).toThrow()
  })
})

// Functional tests of apply.sh against a temp ROOT with stubbed system tools.
describe('apply.sh', () => {
  let tmp: string
  let root: string
  let log: string
  let env: NodeJS.ProcessEnv

  const STUB = `#!/bin/bash
echo "$(basename "$0") $*" >> "$FAKE_LOG"
case "$(basename "$0") $*" in
  "ip -4 -o addr show") for a in $FAKE_ADDRS; do echo "2: eth0    inet $a/24 brd 10.0.0.255 scope global eth0"; done ;;
  "ip link show dev "*) for l in $FAKE_LINKS; do [ "$l" = "$4" ] && { echo "5: $l: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420"; exit 0; }; done; exit 1 ;;
  "ip rule show") printf '0:\\tfrom all lookup local\\n100:\\tfrom all fwmark 0x51 lookup 151\\n101:\\tfrom all fwmark 0x52 lookup 152\\n' ;;
  "systemctl restart "*) [ -n "\${FAIL_RESTART:-}" ] && [ "$2" = "$FAIL_RESTART" ] && exit 1 ;;
esac
exit 0
`
  const iface = (port: number, peers: string[]) =>
    `[Interface]\nPrivateKey = k\nListenPort = ${port}\n` + peers.map(p => `\n[Peer]\nPublicKey = ${p}\nAllowedIPs = 10.66.0.2/32\n`).join('')

  const files = (awgc: string): RenderedFile[] => [
    { path: `${NODE_PATHS.awgDir}/awgc.conf`, mode: 0o600, content: awgc },
    { path: `${NODE_PATHS.awgDir}/awgt.conf`, mode: 0o600, content: iface(51821, ['T']) },
    { path: NODE_PATHS.nftables, mode: 0o644, content: 'table inet vpn {}\n' },
    { path: NODE_PATHS.sysctl, mode: 0o644, content: 'net.ipv4.ip_forward=1\n' },
    { path: NODE_PATHS.routingScript, mode: 0o755, content: '#!/bin/sh\n' },
    { path: NODE_PATHS.routingUnit, mode: 0o644, content: '[Unit]\n' },
  ]
  const meta: ApplyMeta = {
    node: 'main/local', role: 'local', hash: 'h1', coordinatorVersion: '2.0.0',
    addresses: ['10.0.0.5', '10.0.0.6'], interfaces: ['awgc', 'awgt'],
  }

  function run(fs_: RenderedFile[], m: ApplyMeta = meta) {
    fs.writeFileSync(log, '')
    const stage = path.join(tmp, 'stage')
    fs.mkdirSync(stage)
    execFileSync('tar', ['-xf', '-', '-C', stage], { input: buildApplyBundle(fs_, m) })
    const r = spawnSync('bash', [path.join(stage, 'apply.sh'), stage], { env })
    return {
      status: r.status, stdout: r.stdout.toString(), stderr: r.stderr.toString(),
      calls: fs.readFileSync(log, 'utf8').trim().split('\n'), stageGone: !fs.existsSync(stage),
    }
  }

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'apply-test-'))
    root = path.join(tmp, 'root')
    log = path.join(tmp, 'calls.log')
    const bin = path.join(tmp, 'bin')
    fs.mkdirSync(root)
    fs.mkdirSync(bin)
    for(const name of ['ip', 'systemctl', 'awg', 'awg-quick', 'nft', 'sysctl', 'id', 'useradd', 'chgrp', 'curl']) {
      fs.writeFileSync(path.join(bin, name), STUB, { mode: 0o755 })
    }
    env = {
      PATH: `${bin}:${process.env.PATH}`, ROOT: root, FAKE_LOG: log,
      FAKE_ADDRS: '10.0.0.5 10.0.0.6', FAKE_LINKS: 'awgc awgt',
    }
  })
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }))

  it('fresh apply installs files, restarts interfaces and writes the marker', () => {
    const r = run(files(iface(51820, ['A'])))
    expect(r.stderr).toBe('')
    expect(r.status).toBe(0)
    expect(r.stdout.trim()).toBe('APPLIED h1')
    expect(r.stageGone).toBe(true)
    const conf = path.join(root, NODE_PATHS.awgDir, 'awgc.conf')
    expect(fs.readFileSync(conf, 'utf8')).toBe(iface(51820, ['A']))
    expect(fs.statSync(conf).mode & 0o777).toBe(0o600)
    expect(fs.statSync(path.join(root, NODE_PATHS.routingScript)).mode & 0o777).toBe(0o755)
    expect(r.calls).toContain('sysctl -e --system')
    expect(r.calls).toContain(`nft -f ${root}${NODE_PATHS.nftables}`)
    expect(r.calls).toContain('systemctl restart awg-quick@awgc')
    expect(r.calls).toContain('systemctl restart awg-quick@awgt')
    expect(r.calls).toContain('systemctl daemon-reload')
    expect(r.calls).toContain('systemctl restart vpn-routing')
    const marker = JSON.parse(fs.readFileSync(path.join(root, NODE_PATHS.marker), 'utf8'))
    expect(marker).toMatchObject({ node: 'main/local', role: 'local', appliedHash: 'h1', coordinatorVersion: '2.0.0' })
    expect(marker.appliedAt).toMatch(/^\d{4}-\d\d-\d\dT/)
  })

  it('re-apply of the same files changes nothing (AC-P5)', () => {
    run(files(iface(51820, ['A'])))
    const conf = path.join(root, NODE_PATHS.awgDir, 'awgc.conf')
    const past = new Date(Math.floor(Date.now() / 1000) * 1000 - 100_000)
    fs.utimesSync(conf, past, past)
    const r = run(files(iface(51820, ['A'])))
    expect(r.status).toBe(0)
    expect(Math.round(fs.statSync(conf).mtimeMs)).toBe(past.getTime())
    expect(r.calls.filter(c => /restart|syncconf|sysctl|nft -f|daemon-reload/.test(c))).toEqual([])
    expect(r.calls).toContain('systemctl -q enable --now awg-quick@awgc')
    expect(r.calls).toContain('systemctl -q enable --now vpn-routing')
  })

  it('peers-only change uses awg syncconf without restart (R-P4)', () => {
    run(files(iface(51820, ['A'])))
    const r = run(files(iface(51820, ['A', 'B'])))
    expect(r.status).toBe(0)
    expect(r.calls.some(c => c.startsWith('awg syncconf awgc /dev/fd/'))).toBe(true)
    expect(r.calls).toContain('awg-quick strip awgc')
    expect(r.calls.filter(c => c.includes('restart'))).toEqual([])
  })

  it('peers-only change on a down interface restarts it', () => {
    run(files(iface(51820, ['A'])))
    env.FAKE_LINKS = 'awgt'
    const r = run(files(iface(51820, ['A', 'B'])))
    expect(r.calls).toContain('systemctl restart awg-quick@awgc')
    expect(r.status).toBe(30) // self-check: awgc missing
    expect(r.stderr).toContain('self-check: interface awgc missing')
  })

  it('interface section change restarts the interface', () => {
    run(files(iface(51820, ['A'])))
    const r = run(files(iface(51900, ['A'])))
    expect(r.status).toBe(0)
    expect(r.calls).toContain('systemctl restart awg-quick@awgc')
    expect(r.calls.some(c => c.startsWith('awg syncconf'))).toBe(false)
    expect(r.calls).not.toContain('systemctl restart awg-quick@awgt')
  })

  it('missing address exits 20 before installing anything', () => {
    const r = run(files(iface(51820, ['A'])), { ...meta, addresses: ['10.0.0.5', '10.0.0.66'] })
    expect(r.status).toBe(20)
    expect(r.stderr.trim()).toBe('address 10.0.0.66 not present on host')
    expect(fs.readdirSync(root)).toEqual([])
    expect(r.calls).toEqual(['ip -4 -o addr show'])
  })

  it('does not match an address as a prefix of another', () => {
    env.FAKE_ADDRS = '10.0.0.50 10.0.0.6'
    const r = run(files(iface(51820, ['A'])))
    expect(r.status).toBe(20)
  })

  it('LOCAL self-check requires the fwmark rules; REMOTE does not', () => {
    const stubDir = path.join(tmp, 'bin')
    // An `ip` that reports no rules.
    fs.writeFileSync(path.join(stubDir, 'ip'), STUB.replace(/"ip rule show"\).*\n/, '"ip rule show") ;;\n'), { mode: 0o755 })
    const local = run(files(iface(51820, ['A'])))
    expect(local.status).toBe(30)
    expect(local.stderr).toContain('fwmark 0x51')
    const remote = run(files(iface(51820, ['A'])), { ...meta, role: 'remote' })
    expect(remote.status).toBe(0)
  })

  it('a failed restart leaves the change pending, so the retry restarts again', () => {
    run(files(iface(51820, ['A'])))
    const pending = path.join(root, NODE_PATHS.marker.replace(/[^/]+$/, 'pending'))
    expect(fs.existsSync(pending)).toBe(false)
    const changedFiles = files(iface(51900, ['A']))
    changedFiles[3] = { ...changedFiles[3], content: 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n' }
    env.FAIL_RESTART = 'awg-quick@awgc'
    const failed = run(changedFiles, { ...meta, hash: 'h2' })
    expect(failed.status).toBe(31)
    expect(fs.readFileSync(pending, 'utf8').trim().split('\n').sort())
      .toEqual([`${NODE_PATHS.awgDir}/awgc.conf`, NODE_PATHS.sysctl].sort())
    expect(JSON.parse(fs.readFileSync(path.join(root, NODE_PATHS.marker), 'utf8')).appliedHash).toBe('h1')

    delete env.FAIL_RESTART
    const retry = run(changedFiles, { ...meta, hash: 'h2' })
    expect(retry.status).toBe(0)
    expect(retry.calls).toContain('systemctl restart awg-quick@awgc')
    expect(retry.calls).toContain('sysctl -e --system')
    expect(retry.calls.some(c => c.startsWith('awg syncconf'))).toBe(false)
    expect(retry.calls).not.toContain('systemctl restart awg-quick@awgt')
    expect(fs.existsSync(pending)).toBe(false)
    expect(JSON.parse(fs.readFileSync(path.join(root, NODE_PATHS.marker), 'utf8')).appliedHash).toBe('h2')

    // Once applied, the same stage is a no-op again.
    const again = run(changedFiles, { ...meta, hash: 'h2' })
    expect(again.calls.filter(c => /restart|syncconf|sysctl|nft -f|daemon-reload/.test(c))).toEqual([])
  })

  it('a pending peers-only change restarts instead of syncconf', () => {
    run(files(iface(51820, ['A'])))
    env.FAIL_RESTART = 'awg-quick@awgc'
    expect(run(files(iface(51900, ['A']))).status).toBe(31)
    delete env.FAIL_RESTART
    // Peers-only relative to the installed-but-never-applied file; the live interface still has 51820.
    const r = run(files(iface(51900, ['A', 'B'])))
    expect(r.status).toBe(0)
    expect(r.calls).toContain('systemctl restart awg-quick@awgc')
    expect(r.calls.some(c => c.startsWith('awg syncconf'))).toBe(false)
  })

  it('a LOCAL host reused as REMOTE drops awgc and vpn-routing', () => {
    run(files(iface(51820, ['A'])))
    const remoteFiles = files(iface(51820, ['A'])).filter(f => /awgt\.conf$|nftables|sysctl/.test(f.path))
    const r = run(remoteFiles, { ...meta, node: 'main/remote', role: 'remote', interfaces: ['awgt'] })
    expect(r.stderr).toBe('')
    expect(r.status).toBe(0)
    expect(r.calls).toContain('systemctl -q disable --now vpn-routing awg-quick@awgc')
    expect(r.calls).toContain('systemctl daemon-reload')
    expect(r.calls.filter(c => c.includes('vpn-routing') && !c.includes('disable'))).toEqual([])
    for(const p of [`${NODE_PATHS.awgDir}/awgc.conf`, NODE_PATHS.routingScript, NODE_PATHS.routingUnit]) {
      expect(fs.existsSync(path.join(root, p))).toBe(false)
    }
    expect(fs.existsSync(path.join(root, NODE_PATHS.awgDir, 'awgt.conf'))).toBe(true)
    // Nothing left to clean up on the next run.
    const again = run(remoteFiles, { ...meta, node: 'main/remote', role: 'remote', interfaces: ['awgt'] })
    expect(again.status).toBe(0)
    expect(again.calls.filter(c => /disable|daemon-reload|vpn-routing/.test(c))).toEqual([])
  })
})

describe('apply.sh with the SOCKS5 proxy (R-L8)', () => {
  let tmp: string
  let root: string
  let log: string
  let env: NodeJS.ProcessEnv

  const STUB = `#!/bin/bash
echo "$(basename "$0") $*" >> "$FAKE_LOG"
case "$(basename "$0") $*" in
  "ip -4 -o addr show") echo "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0" ;;
  "ip link show dev "*) echo "5: $4: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420" ;;
  "ip rule show") printf '100:\\tfrom all fwmark 0x51 lookup 151\\n101:\\tfrom all fwmark 0x52 lookup 152\\n' ;;
  "id -u vpn-socks") [ -n "\${NO_USER:-}" ] && exit 1 ;;
  "curl "*) while [ $# -gt 0 ]; do [ "$1" = -o ] && { echo fake > "$2"; }; shift; done ;;
esac
exit 0
`
  const base: RenderedFile[] = [
    { path: `${NODE_PATHS.awgDir}/awgc.conf`, mode: 0o600, content: '[Interface]\nListenPort = 1\n' },
    { path: `${NODE_PATHS.awgDir}/awgt.conf`, mode: 0o600, content: '[Interface]\nListenPort = 2\n' },
    { path: NODE_PATHS.nftables, mode: 0o644, content: 'table inet vpn {}\n' },
    { path: NODE_PATHS.routingScript, mode: 0o755, content: '#!/bin/sh\n' },
    { path: NODE_PATHS.routingUnit, mode: 0o644, content: '[Unit]\n' },
  ]
  const socks = (users = 'alice A1\n', conf = 'services: []\n'): RenderedFile[] => [
    ...base,
    { path: NODE_PATHS.socksConf, mode: 0o640, content: conf },
    { path: NODE_PATHS.socksUsers, mode: 0o640, content: users },
    { path: NODE_PATHS.socksUnit, mode: 0o644, content: '[Unit]\n' },
  ]
  const meta: ApplyMeta = {
    node: 'main/local', role: 'local', hash: 'h', coordinatorVersion: '2', addresses: ['10.0.0.5'], interfaces: ['awgc', 'awgt'],
  }

  function run(files: RenderedFile[], m: ApplyMeta = meta) {
    fs.writeFileSync(log, '')
    const stage = path.join(tmp, 'stage')
    fs.mkdirSync(stage)
    execFileSync('tar', ['-xf', '-', '-C', stage], { input: buildApplyBundle(files, m) })
    const r = spawnSync('bash', [path.join(stage, 'apply.sh'), stage], { env })
    return { status: r.status, stderr: r.stderr.toString(), calls: fs.readFileSync(log, 'utf8').trim().split('\n') }
  }

  function fakeGost(version: string) {
    const bin = path.join(root, NODE_PATHS.gostBin)
    fs.mkdirSync(path.dirname(bin), { recursive: true })
    fs.writeFileSync(bin, `#!/bin/sh\necho "gost v${version} (go1.26 linux/amd64)"\n`, { mode: 0o755 })
  }

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'apply-socks-'))
    root = path.join(tmp, 'root')
    log = path.join(tmp, 'calls.log')
    const bin = path.join(tmp, 'bin')
    fs.mkdirSync(root)
    fs.mkdirSync(bin)
    for(const name of ['ip', 'systemctl', 'awg', 'awg-quick', 'nft', 'sysctl', 'id', 'useradd', 'chgrp', 'curl']) {
      fs.writeFileSync(path.join(bin, name), STUB, { mode: 0o755 })
    }
    env = { PATH: `${bin}:${process.env.PATH}`, ROOT: root, FAKE_LOG: log }
  })
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }))

  it('first apply creates the user, hands the files to its group and starts the proxy', () => {
    fakeGost(GOST.version)
    env.NO_USER = '1'
    const r = run(socks())
    expect(r.stderr).toBe('')
    expect(r.status).toBe(0)
    expect(r.calls).toContain('useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vpn-socks')
    expect(r.calls.filter(c => c.startsWith('curl'))).toEqual([])
    expect(r.calls).toContain(`chgrp vpn-socks ${root}${NODE_PATHS.socksUsers}.vpn-new`)
    expect(r.calls).toContain(`chgrp vpn-socks ${root}${NODE_PATHS.socksConf}.vpn-new`)
    expect(r.calls.filter(c => c.startsWith('chgrp'))).toHaveLength(2)
    expect(r.calls).toContain('systemctl restart vpn-socks')
    expect(r.calls).toContain('systemctl -q is-active vpn-socks')
    // The user exists before nftables (which names it) is loaded.
    expect(r.calls.findIndex(c => c.startsWith('useradd'))).toBeLessThan(r.calls.findIndex(c => c.startsWith('nft -f')))
    expect(fs.statSync(path.join(root, NODE_PATHS.socksUsers)).mode & 0o777).toBe(0o640)
  })

  it('a users-only change restarts nothing: gost re-reads the file', () => {
    fakeGost(GOST.version)
    run(socks())
    const r = run(socks('alice A1\nbob B2\n'))
    expect(r.status).toBe(0)
    expect(fs.readFileSync(path.join(root, NODE_PATHS.socksUsers), 'utf8')).toBe('alice A1\nbob B2\n')
    expect(r.calls.filter(c => /restart|daemon-reload/.test(c))).toEqual([])
    expect(r.calls).toContain('systemctl -q enable --now vpn-socks')
    expect(r.calls).not.toContain('useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vpn-socks')
  })

  it('a conf change restarts the proxy', () => {
    fakeGost(GOST.version)
    run(socks())
    const r = run(socks('alice A1\n', 'services: [x]\n'))
    expect(r.calls).toContain('systemctl restart vpn-socks')
    expect(r.calls.filter(c => c.includes('restart awg-quick'))).toEqual([])
  })

  it('a missing or old gost is downloaded and its sha256 checked; a failure leaves only the proxy pending', () => {
    fakeGost('3.0.0')
    const r = run(socks())
    expect(r.calls.some(c => c.startsWith('curl ') && c.includes(`/v${GOST.version}/gost_${GOST.version}_linux_`))).toBe(true)
    // The stubbed download is not the real archive.
    expect(r.status).toBe(33)
    expect(r.stderr).toContain('gost download: sha256 mismatch')
    // The VPN itself was applied before the proxy step.
    expect(r.calls).toContain(`nft -f ${root}${NODE_PATHS.nftables}`)
    expect(r.calls).toContain('systemctl restart awg-quick@awgc')
    expect(r.calls.filter(c => c.startsWith('systemctl') && c.includes('vpn-socks'))).toEqual([])
    const pending = path.join(root, NODE_PATHS.marker.replace(/[^/]+$/, 'pending'))
    expect(fs.readFileSync(pending, 'utf8').trim().split('\n')).toEqual([NODE_PATHS.socksConf, NODE_PATHS.socksUnit])
    expect(fs.existsSync(path.join(root, NODE_PATHS.marker))).toBe(false)

    // The retry touches only the proxy.
    fakeGost(GOST.version)
    const retry = run(socks())
    expect(retry.stderr).toBe('')
    expect(retry.status).toBe(0)
    expect(retry.calls.filter(c => /restart/.test(c))).toEqual(['systemctl restart vpn-socks'])
    expect(fs.existsSync(pending)).toBe(false)
    expect(fs.existsSync(path.join(root, NODE_PATHS.marker))).toBe(true)
  })

  it('a proxy that does not stay up fails the apply', () => {
    fakeGost(GOST.version)
    const stub = path.join(tmp, 'bin', 'systemctl')
    fs.writeFileSync(stub, STUB.replace('exit 0\n`', '').replace(/exit 0\n$/, '[ "$*" = "-q is-active vpn-socks" ] && exit 3\nexit 0\n'), { mode: 0o755 })
    const r = run(socks())
    expect(r.status).toBe(33)
    expect(r.stderr).toContain('vpn-socks not running')
  })

  it('turning the proxy off stops it and removes its files', () => {
    fakeGost(GOST.version)
    run(socks())
    const r = run(base)
    expect(r.stderr).toBe('')
    expect(r.status).toBe(0)
    expect(r.calls).toContain('systemctl -q disable --now vpn-socks')
    expect(r.calls).toContain('systemctl daemon-reload')
    expect(fs.existsSync(path.join(root, NODE_PATHS.socksDir))).toBe(false)
    expect(fs.existsSync(path.join(root, NODE_PATHS.socksUnit))).toBe(false)
    expect(run(base).calls.filter(c => c.includes('vpn-socks'))).toEqual([])
  })

  it('a LOCAL host reused as REMOTE drops the proxy too', () => {
    fakeGost(GOST.version)
    run(socks())
    const r = run(base.filter(f => f.path.endsWith('awgt.conf') || f.path === NODE_PATHS.nftables),
      { ...meta, node: 'main/remote', role: 'remote', interfaces: ['awgt'] })
    expect(r.status).toBe(0)
    expect(r.calls).toContain('systemctl -q disable --now vpn-socks')
    expect(fs.existsSync(path.join(root, NODE_PATHS.socksUsers))).toBe(false)
  })
})

describe('retireScript', () => {
  let tmp: string

  function run(hostAddrs: string, current: string[]) {
    const bin = path.join(tmp, 'bin')
    const log = path.join(tmp, 'calls.log')
    fs.mkdirSync(bin, { recursive: true })
    fs.writeFileSync(path.join(bin, 'ip'), `#!/bin/sh\nfor a in ${hostAddrs}; do echo "2: eth0    inet $a/24 brd x scope global eth0"; done\n`, { mode: 0o755 })
    for(const name of ['systemctl', 'rm']) {
      fs.writeFileSync(path.join(bin, name), `#!/bin/sh\necho "${name} $*" >> ${log}\n`, { mode: 0o755 })
    }
    const r = spawnSync('bash', ['-s'], { input: retireScript(current), env: { PATH: `${bin}:${process.env.PATH}` } })
    return { status: r.status, stdout: r.stdout.toString(), calls: fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : [] }
  }

  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'retire-test-')) })
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }))

  it('stops the interfaces and drops the marker on a replaced host', () => {
    const r = run('198.51.100.7 198.51.100.8', ['203.0.113.10', '203.0.113.1'])
    expect(r.status).toBe(0)
    expect(r.stdout.trim()).toBe('RETIRED')
    expect(r.calls).toEqual([
      'systemctl disable --now awg-quick@awgc',
      'systemctl disable --now awg-quick@awgt',
      'systemctl disable --now vpn-routing',
      'systemctl disable --now vpn-socks',
      `rm -f ${NODE_PATHS.marker}`,
    ])
  })

  it('leaves the host alone when it still holds a current address', () => {
    // 203.0.113.1 must not match 203.0.113.10: the prefix length follows the address.
    const r = run('203.0.113.10 198.51.100.8', ['203.0.113.1', '203.0.113.10'])
    expect(r.status).toBe(0)
    expect(r.stdout.trim()).toBe('SAME_HOST')
    expect(r.calls).toEqual([])
    expect(run('203.0.113.10', ['203.0.113.1']).stdout.trim()).toBe('RETIRED')
  })
})
