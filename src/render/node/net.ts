// Tiny IPv4/CIDR helpers shared by the node renderers.

import { intToIp, ipToInt } from '../../geo/cidr'

function parseCidr(cidr: string): { base: number, len: number } {
  const [ip, lenStr] = cidr.split('/')
  const len = Number(lenStr)
  if(lenStr === undefined || !/^\d{1,2}$/.test(lenStr) || len > 32) throw new Error(`invalid CIDR: ${cidr}`)
  const size = 2 ** (32 - len)
  return { base: Math.floor(ipToInt(ip) / size) * size, len }
}

export function prefixLen(cidr: string): number {
  return parseCidr(cidr).len
}

/** n-th address of the subnet: subnetHost('10.255.0.0/30', 1) === '10.255.0.1'. */
export function subnetHost(cidr: string, n: number): string {
  const { base, len } = parseCidr(cidr)
  if(!Number.isInteger(n) || n < 0 || n >= 2 ** (32 - len)) throw new Error(`host ${n} out of range for ${cidr}`)
  return intToIp(base + n)
}
