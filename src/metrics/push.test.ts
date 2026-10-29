import http from 'http'
import type { AddressInfo } from 'net'
import { afterEach, describe, expect, it } from 'vitest'
import { ALERT_AFTER_FAILURES, MetricsPusher, pushMetrics } from './push'

interface Received { method?: string, url?: string, auth?: string, type?: string, body: string }

let server: http.Server | undefined
afterEach(() => server?.close())

async function receiver(status = 204): Promise<{ url: string, got: Received[], setStatus: (s: number) => void }> {
  const got: Received[] = []
  let code = status
  server = http.createServer((req, res) => {
    let body = ''
    req.on('data', chunk => { body += chunk })
    req.on('end', () => {
      got.push({ method: req.method, url: req.url, auth: req.headers.authorization, type: req.headers['content-type'], body })
      res.writeHead(code).end(code >= 400 ? 'bad auth' : '')
    })
  })
  await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  return { url: `http://127.0.0.1:${port}/api/v1/import/prometheus`, got, setStatus: s => { code = s } }
}

describe('pushMetrics', () => {
  it('POSTs the exposition with basic auth', async () => {
    const r = await receiver()
    await pushMetrics({ url: r.url, username: 'vpn', password: 'p:w' }, 'vpn_users{status="active"} 3\n')
    expect(r.got).toEqual([{
      method: 'POST',
      url: '/api/v1/import/prometheus',
      auth: `Basic ${Buffer.from('vpn:p:w').toString('base64')}`,
      type: 'text/plain; version=0.0.4; charset=utf-8',
      body: 'vpn_users{status="active"} 3\n',
    }])
  })

  it('sends no auth header without credentials and throws on an error status', async () => {
    const r = await receiver(401)
    await expect(pushMetrics({ url: r.url }, 'x 1\n')).rejects.toThrow('HTTP 401: bad auth')
    expect(r.got[0].auth).toBeUndefined()
  })
})

describe('MetricsPusher', () => {
  it('does nothing without a target, alerts once after a long outage and on recovery', async () => {
    const r = await receiver(500)
    const alerts: string[] = []
    let target: { url: string } | undefined
    const pusher = new MetricsPusher({ target: () => target, render: async () => 'x 1\n', alert: t => alerts.push(t) })

    await pusher.tick()
    expect(r.got).toHaveLength(0)

    target = { url: r.url }
    for(let i = 0; i < ALERT_AFTER_FAILURES + 3; i++) await pusher.tick()
    expect(alerts).toHaveLength(1)
    expect(alerts[0]).toContain(`уже ${ALERT_AFTER_FAILURES} мин`)

    r.setStatus(204)
    await pusher.tick()
    await pusher.tick()
    expect(alerts).toEqual([alerts[0], 'метрики снова отправляются'])
  })
})
