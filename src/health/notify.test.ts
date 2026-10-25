import { describe, expect, it } from 'vitest'
import { adminTransitionMessage, announceMessage, nextAnnouncement } from './notify'

describe('messages', () => {
  it('builds admin and announce texts', () => {
    expect(adminTransitionMessage('main', 'ok', 'degraded')).toBe('площадка main: ok → degraded (туннель до REMOTE не отвечает, работает только домашний трафик)')
    expect(adminTransitionMessage('main', 'ok', 'down', 'LOCAL: x')).toContain('\nLOCAL: x')
    expect(announceMessage('degraded')).toBe('Зарубежные сайты сейчас недоступны, остальное работает. Уже чиним.')
    expect(announceMessage('down')).toBe('VPN сейчас недоступен. Уже чиним.')
    expect(announceMessage('ok')).toBe('VPN снова работает полностью.')
  })
})

describe('nextAnnouncement', () => {
  const delay = 5 * 60_000

  it('announces an outage only after it has lasted the delay', () => {
    expect(nextAnnouncement('ok', 'down', 0, delay)).toBeNull()
    expect(nextAnnouncement('ok', 'down', delay - 1, delay)).toBeNull()
    expect(nextAnnouncement('ok', 'down', delay, delay)).toBe('down')
    expect(nextAnnouncement('down', 'degraded', delay, delay)).toBe('degraded')
    expect(nextAnnouncement('ok', 'degraded', 0, 0)).toBe('degraded')
  })

  it('announces recovery right away, and only after an announced outage', () => {
    expect(nextAnnouncement('down', 'ok', 0, delay)).toBe('ok')
    expect(nextAnnouncement('ok', 'ok', delay, delay)).toBeNull()
    expect(nextAnnouncement('down', 'down', delay, delay)).toBeNull()
  })
})
