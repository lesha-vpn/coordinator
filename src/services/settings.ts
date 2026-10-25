import { now, type Db } from '../db'

// Admin-set values kept in the DB (and so in backups), changed from the bot without a restart.

const DOWNLOAD_URL = 'download_url'
const URL_MAX = 2048

export function getSetting(db: Db, key: string): string | null {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined
  return row?.value ?? null
}

export function setSetting(db: Db, key: string, value: string, by?: number) {
  db.prepare(`
    INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by
  `).run(key, value, now(), by ?? null)
}

/** The http(s) URL in canonical form, or null if it isn't one. */
export function normalizeDownloadUrl(text: string): string | null {
  if(text.length > URL_MAX) return null
  try {
    const url = new URL(text)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null
  } catch {
    return null
  }
}

/** R-A12: where GET /download redirects; null until an admin sets it. */
export function getDownloadUrl(db: Db): string | null {
  return getSetting(db, DOWNLOAD_URL)
}

export function setDownloadUrl(db: Db, url: string, by?: number) {
  setSetting(db, DOWNLOAD_URL, url, by)
}
