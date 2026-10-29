// Pushes the exposition to a remote VictoriaMetrics (POST /api/v1/import/prometheus) once a
// minute (R-O7). Nothing listens on the coordinator; storage and Grafana live on another server.
// The target is re-read every tick, so editing metrics.push in config.yaml needs no restart.

export const PUSH_INTERVAL_MS = 60_000
export const PUSH_TIMEOUT_MS = 15_000
/** Consecutive failed pushes (minutes) before admins hear about it; a stats outage isn't urgent. */
export const ALERT_AFTER_FAILURES = 30

export interface PushTarget {
  url: string
  username?: string
  password?: string
}

export async function pushMetrics(target: PushTarget, body: string, fetchImpl: typeof fetch = fetch): Promise<void> {
  const headers: Record<string, string> = { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' }
  if(target.username !== undefined || target.password !== undefined) {
    headers.Authorization = `Basic ${Buffer.from(`${target.username ?? ''}:${target.password ?? ''}`).toString('base64')}`
  }
  const res = await fetchImpl(target.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(PUSH_TIMEOUT_MS) })
  if(!res.ok) {
    const text = (await res.text().catch(() => '')).trim().slice(0, 200)
    throw new Error(`HTTP ${res.status}${text ? `: ${text}` : ''}`)
  }
}

export interface PusherDeps {
  target: () => PushTarget | undefined
  render: () => Promise<string>
  alert: (text: string) => void
  log?: (msg: string) => void
  fetch?: typeof fetch
}

export class MetricsPusher {
  private failures = 0
  private alerted = false
  private running = false
  private timer: NodeJS.Timeout | null = null

  constructor(private readonly deps: PusherDeps) {}

  start(intervalMs = PUSH_INTERVAL_MS): void {
    this.timer = setInterval(() => void this.tick(), intervalMs)
  }

  stop(): void {
    if(this.timer) clearInterval(this.timer)
    this.timer = null
  }

  async tick(): Promise<void> {
    const target = this.deps.target()
    if(!target || this.running) return
    this.running = true
    try {
      await pushMetrics(target, await this.deps.render(), this.deps.fetch)
      if(this.alerted) this.deps.alert('метрики снова отправляются')
      this.failures = 0
      this.alerted = false
    } catch(err) {
      const message = err instanceof Error ? err.message : String(err)
      this.failures += 1
      this.deps.log?.(`metrics push to ${target.url} failed: ${message}`)
      if(this.failures >= ALERT_AFTER_FAILURES && !this.alerted) {
        this.alerted = true
        this.deps.alert(`метрики не отправляются на ${target.url} уже ${this.failures} мин: ${message}\nVPN это не затрагивает, пропадут только точки на графиках.`)
      }
    } finally {
      this.running = false
    }
  }
}
