import { NFT_TABLE } from '../render/node/input'
import { ACCT_SETS } from '../render/node/nftables'

// Per-client byte counters of LOCAL (R-O7): the forward chain feeds one dynamic nft set per route
// and direction, an element per client address. Read along with the health probe as
// `__acct__ <set> <nft -j list set ...>`; REMOTE has no such sets and prints an empty JSON part.

export type AcctSet = typeof ACCT_SETS[number]

/** Set → client address → bytes since the last ruleset load. */
export type ClientAcct = Partial<Record<AcctSet, Record<string, number>>>

export const ACCT_SCRIPT = `for s in ${ACCT_SETS.join(' ')}; do echo "__acct__ $s $(nft -j list set inet ${NFT_TABLE} $s 2>/dev/null)"; done`

export const ACCT_LINE = /^__acct__ ([a-z_]+) ?(.*)$/

const isSet = (name: string): name is AcctSet => (ACCT_SETS as readonly string[]).includes(name)

/** Undefined when no set could be read (REMOTE, or nft failed). */
export function parseAcct(lines: string[]): ClientAcct | undefined {
  const acct: ClientAcct = {}
  let found = false

  for(const raw of lines) {
    const m = ACCT_LINE.exec(raw.replace(/\r$/, ''))
    if(!m || !isSet(m[1]) || !m[2].trim()) continue
    let json: unknown
    try { json = JSON.parse(m[2]) } catch { continue }

    const counts: Record<string, number> = {}
    const items = (json as { nftables?: unknown[] }).nftables ?? []
    for(const item of items) {
      const elems = (item as { set?: { elem?: unknown[] } }).set?.elem ?? []
      for(const e of elems) {
        const inner = (e as { elem?: { val?: unknown, counter?: { bytes?: unknown } } }).elem
        if(typeof inner?.val === 'string' && typeof inner.counter?.bytes === 'number') counts[inner.val] = inner.counter.bytes
      }
    }
    acct[m[1]] = counts
    found = true
  }

  return found ? acct : undefined
}
