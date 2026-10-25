import type { NetworkState } from '../types'

// R-H4 wording. Admin text is technical; the users' chat gets a short plain phrase.

const ADMIN_REASON: Record<NetworkState, string> = {
  ok: 'всё работает',
  degraded: 'туннель до REMOTE не отвечает, работает только домашний трафик',
  down: 'LOCAL недоступен',
}

const ANNOUNCE: Record<NetworkState, string> = {
  ok: 'VPN снова работает полностью.',
  degraded: 'Зарубежные сайты сейчас недоступны, остальное работает. Уже чиним.',
  down: 'VPN сейчас недоступен. Уже чиним.',
}

export function adminTransitionMessage(site: string, from: NetworkState, to: NetworkState, detail?: string): string {
  return `площадка ${site}: ${from} → ${to} (${ADMIN_REASON[to]})` + (detail ? `\n${detail}` : '')
}

export function announceMessage(state: NetworkState): string {
  return ANNOUNCE[state]
}

/**
 * Users'-chat announcement policy (R-H4), pure. `announced` is what the chat was last told,
 * `confirmed` the debounced state and `sinceMs` how long it has held. An outage (or a change
 * between degraded and down) is announced once it has lasted `delayMs`; recovery is announced
 * right away, but only if the outage itself was announced. Returns the state to announce, or null.
 */
export function nextAnnouncement(announced: NetworkState, confirmed: NetworkState, sinceMs: number, delayMs: number): NetworkState | null {
  if(confirmed === announced) return null
  if(confirmed === 'ok') return 'ok'

  return sinceMs >= delayMs ? confirmed : null
}
