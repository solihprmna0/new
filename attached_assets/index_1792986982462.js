'use strict'
// QiosPay Node.js SDK — tanpa dependensi (Node 18+, memakai fetch bawaan).
const crypto = require('crypto')

class QiosPayError extends Error {
  constructor(message, code, status) {
    super(message)
    this.name = 'QiosPayError'
    this.code = code
    this.status = status
  }
}

class QiosPay {
  /** @param {string} apiKey qp_live_… / qp_test_…  @param {{baseUrl?: string, timeoutMs?: number}} [opts] */
  constructor(apiKey, opts = {}) {
    if (!apiKey) throw new Error('apiKey wajib diisi')
    this.apiKey = apiKey
    this.baseUrl = (opts.baseUrl || 'https://app.qiospay.com').replace(/\/$/, '')
    this.timeoutMs = opts.timeoutMs || 20000
  }

  createInvoice(params) { return this._req('POST', '/v1/invoices', params) }
  getInvoice(idOrRef) { return this._req('GET', `/v1/invoices/${encodeURIComponent(idOrRef)}`) }
  cancelInvoice(id) { return this._req('POST', `/v1/invoices/${encodeURIComponent(id)}/cancel`) }
  simulatePayment(id) { return this._req('POST', `/v1/invoices/${encodeURIComponent(id)}/simulate`) }
  listInvoices(query = {}) { const q = new URLSearchParams(query).toString(); return this._req('GET', `/v1/invoices${q ? `?${q}` : ''}`) }
  me() { return this._req('GET', '/v1/me') }

  async _req(method, path, body) {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs)
    try {
      const res = await fetch(this.baseUrl + path, {
        method,
        signal: ctrl.signal,
        headers: { Authorization: `Bearer ${this.apiKey}`, Accept: 'application/json', 'User-Agent': 'qiospay-node/1.0.0', ...(body ? { 'Content-Type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      })
      const json = await res.json().catch(() => ({}))
      if (!res.ok) throw new QiosPayError(json.error?.message || `HTTP ${res.status}`, json.error?.code || `HTTP_${res.status}`, res.status)
      return json.data
    } catch (e) {
      if (e instanceof QiosPayError) throw e
      throw new QiosPayError(`Tidak bisa terhubung ke QiosPay: ${e.message}`, 'NETWORK', 0)
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Verifikasi webhook. rawBody HARUS body mentah (Buffer/string), bukan hasil JSON.parse.
   * @returns {object} event
   */
  static verifyWebhook(rawBody, signatureHeader, secret, toleranceSec = 600) {
    const parts = Object.fromEntries(String(signatureHeader || '').split(',').map((p) => p.trim().split('=', 2)).filter((kv) => kv.length === 2))
    if (!parts.t || !parts.v1) throw new QiosPayError('Header X-QiosPay-Signature tidak ada / rusak', 'BAD_SIGNATURE', 400)
    if (toleranceSec > 0 && Math.abs(Date.now() / 1000 - Number(parts.t)) > toleranceSec) throw new QiosPayError('Timestamp webhook kedaluwarsa', 'BAD_SIGNATURE', 400)
    const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody))
    const expected = crypto.createHmac('sha256', secret).update(Buffer.concat([Buffer.from(`${parts.t}.`), body])).digest('hex')
    const a = Buffer.from(expected), b = Buffer.from(parts.v1)
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new QiosPayError('Tanda tangan webhook tidak cocok', 'BAD_SIGNATURE', 401)
    return JSON.parse(body.toString('utf8'))
  }
}

module.exports = QiosPay
module.exports.QiosPay = QiosPay
module.exports.QiosPayError = QiosPayError
