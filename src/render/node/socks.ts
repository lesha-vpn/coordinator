import type { LocalRenderInput, SocksRenderInput } from './input'
import { NODE_PATHS, SOCKS_USER } from './input'

// SOCKS5 proxy on LOCAL (R-L8): gost as user vpn-socks. Where its connections go is decided by
// nftables (nftables.ts), not by gost, the same way as for awgc clients.

/** gost reads the users file again this often, so account changes apply without dropping sessions. */
export const SOCKS_USERS_RELOAD = '10s'

function bareIp(addr: string): string {
  return addr.split('/')[0]
}

export function renderSocksConf(input: LocalRenderInput, socks: SocksRenderInput): string {
  // JSON strings are valid YAML scalars; every value here is ours, but quoting keeps it unambiguous.
  const q = (s: string) => JSON.stringify(s)
  return [
    `# Managed by vpn-coordinator (${input.node}). Do not edit.`,
    'services:',
    '  - name: socks5',
    `    addr: ${q(`${bareIp(input.addresses.client)}:${socks.port}`)}`,
    '    resolver: dns',
    '    handler:',
    '      type: socks5',
    '      auther: users',
    '    listener:',
    '      type: tcp',
    'authers:',
    '  - name: users',
    '    file:',
    `      path: ${q(NODE_PATHS.socksUsers)}`,
    `    reload: ${SOCKS_USERS_RELOAD}`,
    'resolvers:',
    '  - name: dns',
    '    nameservers:',
    ...socks.dns.flatMap(ip => [`      - addr: ${q(`udp://${ip}:53`)}`, '        prefer: ipv4']),
    'log:',
    '  level: warn',
    '',
  ].join('\n')
}

/** gost auth file: `login password` per line. Logins are [A-Za-z0-9_], passwords [A-Za-z0-9]. */
export function renderSocksUsers(socks: SocksRenderInput): string {
  for(const u of socks.users) {
    if(!/^[A-Za-z0-9_]+$/.test(u.login) || !/^[A-Za-z0-9]+$/.test(u.password)) {
      throw new Error(`socks: bad account ${u.login}`)
    }
  }
  return socks.users.map(u => `${u.login} ${u.password}\n`).join('')
}

export function renderSocksUnit(): string {
  return `# Managed by vpn-coordinator. Do not edit.
[Unit]
Description=VPN node SOCKS5 proxy
After=network-online.target vpn-routing.service
Wants=network-online.target

[Service]
User=${SOCKS_USER}
Group=${SOCKS_USER}
ExecStart=${NODE_PATHS.gostBin} -C ${NODE_PATHS.socksConf}
Restart=always
RestartSec=2
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
`
}
