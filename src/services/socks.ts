import { randomInt } from 'node:crypto'
import type { AppContext } from '../context'
import type { Db } from '../db'
import { now } from '../db'
import type { SocksUser } from '../render/node/input'

// SOCKS5 proxy accounts (R-L8): one per user, login = Telegram username, served by every LOCAL.

export const SOCKS_PASSWORD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
export const SOCKS_PASSWORD_LENGTH = 16

export interface SocksAccountRow {
  tg_id: number
  login: string
  password: string
  created_at: string
  updated_at: string
}

export function genSocksPassword(): string {
  let s = ''
  for(let i = 0; i < SOCKS_PASSWORD_LENGTH; i++) s += SOCKS_PASSWORD_ALPHABET[randomInt(SOCKS_PASSWORD_ALPHABET.length)]
  return s
}

export function getSocksAccount(db: Db, tgId: number): SocksAccountRow | null {
  return (db.prepare('SELECT * FROM socks_accounts WHERE tg_id = ?').get(tgId) as SocksAccountRow | undefined) ?? null
}

/**
 * The Telegram username when it's free; `tg<id>` without a username or when another account
 * still holds it (usernames move between people, logins don't).
 */
function pickLogin(db: Db, tgId: number, username: string | null): string {
  if(username && /^[A-Za-z0-9_]{1,64}$/.test(username)) {
    const taken = db.prepare('SELECT 1 FROM socks_accounts WHERE login = ? AND tg_id != ?').get(username, tgId)
    if(!taken) return username
  }
  return `tg${tgId}`
}

export type SocksAccountError = 'not_member'

function activeUser(db: Db, tgId: number): { username: string | null } | null {
  const user = db.prepare('SELECT username, status, revoked_at FROM users WHERE tg_id = ?').get(tgId) as
    { username: string | null, status: string, revoked_at: string | null } | undefined
  return user && user.status === 'active' && !user.revoked_at ? user : null
}

/** The user's account, created on first call. */
export function ensureSocksAccount(ctx: AppContext, tgId: number): SocksAccountRow | { error: SocksAccountError } {
  const result = ctx.db.transaction((): { row: SocksAccountRow, created: boolean } | { error: SocksAccountError } => {
    const user = activeUser(ctx.db, tgId)
    if(!user) return { error: 'not_member' }
    const existing = getSocksAccount(ctx.db, tgId)
    if(existing) return { row: existing, created: false }
    const at = now()
    ctx.db.prepare('INSERT INTO socks_accounts (tg_id, login, password, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .run(tgId, pickLogin(ctx.db, tgId, user.username), genSocksPassword(), at, at)
    return { row: getSocksAccount(ctx.db, tgId)!, created: true }
  })()

  if('error' in result) return result
  if(result.created) ctx.events.emit('peers-changed')
  return result.row
}

/** New password; the login follows the current username. The old password stops working on the next apply. */
export function resetSocksAccount(ctx: AppContext, tgId: number): SocksAccountRow | { error: SocksAccountError } {
  const result = ctx.db.transaction((): SocksAccountRow | { error: SocksAccountError } => {
    const user = activeUser(ctx.db, tgId)
    if(!user) return { error: 'not_member' }
    const at = now()
    const login = pickLogin(ctx.db, tgId, user.username)
    const password = genSocksPassword()
    ctx.db.prepare(`
      INSERT INTO socks_accounts (tg_id, login, password, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (tg_id) DO UPDATE SET login = excluded.login, password = excluded.password, updated_at = excluded.updated_at
    `).run(tgId, login, password, at, at)
    return getSocksAccount(ctx.db, tgId)!
  })()

  if(!('error' in result)) ctx.events.emit('peers-changed')
  return result
}

export function hasSocksAccount(db: Db, tgId: number): boolean {
  return !!db.prepare('SELECT 1 FROM socks_accounts WHERE tg_id = ?').get(tgId)
}

export function deleteSocksAccount(db: Db, tgId: number): boolean {
  return db.prepare('DELETE FROM socks_accounts WHERE tg_id = ?').run(tgId).changes > 0
}

/** Accounts the proxy accepts: users still in the chat and not revoked (R-B1), like awgc peers. */
export function activeSocksUsers(db: Db): SocksUser[] {
  return (db.prepare(`
    SELECT s.login, s.password FROM socks_accounts s JOIN users u ON u.tg_id = s.tg_id
    WHERE u.status = 'active' AND u.revoked_at IS NULL
    ORDER BY s.login COLLATE NOCASE
  `).all() as { login: string, password: string }[])
}

/** `socks5://login:password@<LOCAL.client>:<port>` per site; empty when the proxy is off. */
export function socksUrls(ctx: AppContext, account: Pick<SocksAccountRow, 'login' | 'password'>): { site: string, url: string }[] {
  const config = ctx.config()
  if(!config.socks) return []
  return config.sites.map(site => ({
    site: site.name,
    url: `socks5://${account.login}:${account.password}@${site.local.addresses.client}:${config.socks!.port}`,
  }))
}
