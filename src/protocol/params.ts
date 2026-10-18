import type { ObfuscationParams } from '../types'

/** Uniform integer in [min, max). */
export type RandInt = (min: number, max: number) => number

// Known AWG keys in the order awg-quick/AmneziaVPN print them; anything else follows alphabetically
// so output stays deterministic.
const PARAM_ORDER = [
  'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
  'I1', 'I2', 'I3', 'I4', 'I5',
  'HeaderProtectionKey', 'ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout',
  'RejectAfterTime', 'KeepaliveTimeout', 'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies',
]

const rank = (k: string) => {
  const i = PARAM_ORDER.indexOf(k)
  return i === -1 ? PARAM_ORDER.length : i
}

/** All entries of `params` in canonical config-file order (empty values included). */
export function orderedParamEntries(params: ObfuscationParams): [string, string][] {
  return Object.entries(params)
    .sort(([a], [b]) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0))
}
