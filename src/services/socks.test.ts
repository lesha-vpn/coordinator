import { describe, expect, it, vi } from 'vitest'
import { openDb } from '../db'
import { createEvents, type AppContext } from '../context'
import type { CoordinatorConfig } from '../config/schema'
import { exampleConfig } from './testFixtures'
import { reactivateUser, revokeUser, suspendUser, upsertUser } from './users'
import {
  SOCKS_PASSWORD_LENGTH, activeSocksUsers, ensureSocksAccount, genSocksPassword, getSocksAccount, resetSocksAccount, socksUrls,
} from './socks'

function setup(socks: CoordinatorConfig['socks'] | null = { port: 1080 }) {
  const db = openDb(':memory:')
  const config = { ...exampleConfig(), socks: socks ?? undefined }
  const events = createEvents()
  const peersChanged = vi.fn()
  events.on('peers-changed', peersChanged)
  const ctx: AppContext = { db, config: () => config, events, alert: async () => {} }
  return { ctx, peersChanged }
}

function ensure(ctx: AppContext, tgId: number) {
  const row = ensureSocksAccount(ctx, tgId)
  if('error' in row) throw new Error(row.error)
  return row
}

describe('socks accounts (R-L8)', () => {
  it('passwords are 16 letters/digits', () => {
    const seen = new Set<string>()
    for(let i = 0; i < 200; i++) {
      const p = genSocksPassword()
      expect(p).toMatch(new RegExp(`^[A-Za-z0-9]{${SOCKS_PASSWORD_LENGTH}}$`))
      seen.add(p)
    }
    expect(seen.size).toBe(200)
  })

  it('login is the Telegram username; created once, then shown again', () => {
    const { ctx, peersChanged } = setup()
    upsertUser(ctx.db, 1, 'Alice_99')
    const a = ensure(ctx, 1)
    expect(a.login).toBe('Alice_99')
    expect(peersChanged).toHaveBeenCalledTimes(1)
    expect(ensure(ctx, 1)).toEqual(a)
    expect(peersChanged).toHaveBeenCalledTimes(1)
  })

  it('falls back to tg<id> without a username or when the login is taken', () => {
    const { ctx } = setup()
    upsertUser(ctx.db, 1, null)
    expect(ensure(ctx, 1).login).toBe('tg1')
    upsertUser(ctx.db, 2, 'bob')
    ensure(ctx, 2)
    // bob renamed himself, someone else took "bob": the old account keeps its login
    upsertUser(ctx.db, 2, 'bobby')
    upsertUser(ctx.db, 3, 'BOB')
    expect(ensure(ctx, 3).login).toBe('tg3')
    expect(getSocksAccount(ctx.db, 2)!.login).toBe('bob')
  })

  it('reset makes a new password and takes the current username', () => {
    const { ctx, peersChanged } = setup()
    upsertUser(ctx.db, 1, 'alice')
    const a = ensure(ctx, 1)
    upsertUser(ctx.db, 1, 'alice2')
    const b = resetSocksAccount(ctx, 1)
    if('error' in b) throw new Error(b.error)
    expect(b.login).toBe('alice2')
    expect(b.password).not.toBe(a.password)
    expect(b.created_at).toBe(a.created_at)
    expect(peersChanged).toHaveBeenCalledTimes(2)
  })

  it('refuses users who are not active', () => {
    const { ctx } = setup()
    expect(ensureSocksAccount(ctx, 9)).toEqual({ error: 'not_member' })
    upsertUser(ctx.db, 1, 'alice')
    suspendUser(ctx, 1)
    expect(ensureSocksAccount(ctx, 1)).toEqual({ error: 'not_member' })
    expect(resetSocksAccount(ctx, 1)).toEqual({ error: 'not_member' })
  })

  it('leaving the chat takes the account off the proxy, rejoining brings it back', () => {
    const { ctx, peersChanged } = setup()
    upsertUser(ctx.db, 1, 'alice')
    upsertUser(ctx.db, 2, 'bob')
    const a = ensure(ctx, 1)
    ensure(ctx, 2)
    expect(activeSocksUsers(ctx.db).map(u => u.login)).toEqual(['alice', 'bob'])
    peersChanged.mockClear()

    suspendUser(ctx, 1)
    expect(peersChanged).toHaveBeenCalledTimes(1)
    expect(activeSocksUsers(ctx.db)).toEqual([{ login: 'bob', password: getSocksAccount(ctx.db, 2)!.password }])

    reactivateUser(ctx, 1)
    expect(peersChanged).toHaveBeenCalledTimes(2)
    expect(activeSocksUsers(ctx.db)[0]).toEqual({ login: 'alice', password: a.password })
  })

  it('/revoke_user deletes the account for good', () => {
    const { ctx, peersChanged } = setup()
    upsertUser(ctx.db, 1, 'alice')
    ensure(ctx, 1)
    peersChanged.mockClear()
    expect(revokeUser(ctx, 1)).toMatchObject({ socks: true })
    expect(peersChanged).toHaveBeenCalledTimes(1)
    expect(getSocksAccount(ctx.db, 1)).toBeNull()
    expect(activeSocksUsers(ctx.db)).toEqual([])
  })

  it('URL points at LOCAL.client and the configured port; none when the proxy is off', () => {
    const { ctx } = setup({ port: 4444 })
    expect(socksUrls(ctx, { login: 'alice', password: 'P4ss' }))
      .toEqual([{ site: 'main', url: 'socks5://alice:P4ss@203.0.113.10:4444' }])
    expect(socksUrls(setup(null).ctx, { login: 'alice', password: 'P4ss' })).toEqual([])
  })
})
