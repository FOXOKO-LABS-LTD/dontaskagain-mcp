// HTTP client of the Signer mailbox (agent side). Bearer aw_… token.
// Transport rules: https only (plain http only to loopback / private networks), no credentials in
// the address, redirects are never followed, the response body is bounded, every request has a timeout. Error text
// written by the server is never passed on as our message: the code is checked against a pattern and the server's own
// words are kept apart, bounded and marked as unverified.
import net from 'node:net';
import { E2EError, safeCode, untrusted } from './util.js';

export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public signerSays?: string, public retryAfter?: number) { super(message); }
}

/** Our own text for the codes the Signer is known to answer with. */
const KNOWN: Record<string, string> = {
  UNAUTHORIZED: 'the Signer did not accept DAA_TOKEN (the agent may be revoked or reconnected): ask the human to reconnect the agent in the wallet',
  FORBIDDEN: 'the Signer refused this agent token',
  RATE_LIMITED: 'too many envelopes from this agent: wait (retry_after seconds) and try again; do not create new requests meanwhile',
  MAILBOX_FULL: 'the wallet mailbox is full: the human must open the extension',
  E2E_REQUIRED: 'the Signer accepts only end-to-end requests',
  E2E_DUPLICATE: 'an envelope with this id was already stored with other bytes',
  E2E_BAD_ENVELOPE: 'the Signer rejected the form of the envelope',
  E2E_FROM_MISMATCH: 'the Signer says the envelope header does not match this agent token',
  E2E_VIEW_NOT_SYNCED: 'the wallet has not published its view for this agent yet: the human must open the extension',
  E2E_AGENT_KEY_LOCAL: 'this agent keeps its key locally (npx package); the remote MCP is not for it',
  NOT_FOUND: 'the Signer does not know this path (an old Signer without end-to-end mode?)',
  REDIRECT_REFUSED: 'the Signer answered with a redirect; redirects are not followed — check DAA_URL',
  RESPONSE_TOO_LARGE: 'the Signer answer is larger than allowed; it was dropped',
  BAD_RESPONSE: 'the Signer answer is not JSON',
};
export const ownMessage = (code: string, status: number) => KNOWN[code] ?? `the Signer refused the call (HTTP ${status}, code ${code})`;

function privateIPv4(h: string): boolean {
  const p = h.split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return false;
  return p[0] === 127 || p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168)
    || (p[0] === 100 && p[1] >= 64 && p[1] <= 127); // 100.64/10: CGNAT / VPN overlays
}
/** Loopback or a private network: the only places where plain http is accepted. */
export function isLocalHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (net.isIPv4(h)) return privateIPv4(h);
  if (net.isIPv6(h)) {
    if (h === '::1') return true;
    const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
    if (m) return privateIPv4(m[1]);
    return /^f[cd][0-9a-f]{2}:/.test(h); // fc00::/7 unique local
  }
  return false;
}

/** Validates DAA_URL: https (http only to loopback/private networks), no user:password, no query or fragment. */
export function checkBaseUrl(raw: string): string {
  let u: URL;
  try { u = new URL(raw); } catch { throw new E2EError('E2E_BAD_URL', 'DAA_URL is not a valid URL'); }
  if (u.username || u.password) throw new E2EError('E2E_BAD_URL', 'DAA_URL must not contain a user name or password');
  if (u.search || u.hash) throw new E2EError('E2E_BAD_URL', 'DAA_URL must not contain a query or a fragment');
  if (u.protocol === 'http:') {
    if (!isLocalHost(u.hostname)) throw new E2EError('E2E_BAD_URL', 'DAA_URL must use https:// (plain http:// is accepted only for localhost and private network addresses)');
  } else if (u.protocol !== 'https:') {
    throw new E2EError('E2E_BAD_URL', 'DAA_URL must use https://');
  }
  return (u.origin + u.pathname).replace(/\/+$/, '');
}

export class Api {
  readonly base: string;
  constructor(base: string, private token: string, private timeoutMs = 90_000, private maxBytes = MAX_RESPONSE_BYTES) {
    this.base = checkBaseUrl(base);
  }

  async req(method: string, path: string, body?: unknown, timeoutMs = this.timeoutMs): Promise<{ status: number; body: any }> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    let r: Response;
    try {
      r = await fetch(this.base + path, {
        method, signal: ac.signal, redirect: 'manual',
        headers: { Authorization: `Bearer ${this.token}`, Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e: any) {
      clearTimeout(t);
      throw new ApiError(0, 'UNAVAILABLE', `Signer unreachable (${this.base}): ${e?.name === 'AbortError' ? 'timeout' : 'network error'}`);
    }
    try {
      if (r.type === 'opaqueredirect' || (r.status >= 300 && r.status < 400)) {
        ac.abort();
        throw new ApiError(r.status, 'REDIRECT_REFUSED', ownMessage('REDIRECT_REFUSED', r.status));
      }
      const declared = Number(r.headers.get('content-length') ?? NaN);
      if (Number.isFinite(declared) && declared > this.maxBytes) { ac.abort(); throw new ApiError(r.status, 'RESPONSE_TOO_LARGE', ownMessage('RESPONSE_TOO_LARGE', r.status)); }
      const chunks: Buffer[] = [];
      let size = 0;
      if (r.body) {
        const reader = r.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > this.maxBytes) { ac.abort(); throw new ApiError(r.status, 'RESPONSE_TOO_LARGE', ownMessage('RESPONSE_TOO_LARGE', r.status)); }
          chunks.push(Buffer.from(value));
        }
      }
      const text = Buffer.concat(chunks).toString('utf8');
      let b: any;
      try { b = text ? JSON.parse(text) : {}; } catch { b = { raw: untrusted(text) }; }
      if (b === null || typeof b !== 'object') b = {};
      return { status: r.status, body: b };
    } catch (e: any) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(0, 'UNAVAILABLE', `Signer unreachable (${this.base}): ${e?.name === 'AbortError' ? 'timeout' : 'connection lost'}`);
    } finally { clearTimeout(t); }
  }

  /** An ApiError for an HTTP ≥ 400 answer: checked code, our own message, the server's words apart and bounded. */
  static fromResponse(r: { status: number; body: any }): ApiError {
    const e = r.body?.error && typeof r.body.error === 'object' ? r.body.error : {};
    const code = safeCode(e.code, r.status);
    const ra = Number(e.retry_after);
    return new ApiError(r.status, code, ownMessage(code, r.status), untrusted(e.message ?? r.body?.raw), Number.isFinite(ra) && ra >= 0 && ra < 86400 ? Math.ceil(ra) : undefined);
  }

  /** Like req, but throws ApiError on HTTP ≥ 400. */
  async must(method: string, path: string, body?: unknown, timeoutMs?: number): Promise<any> {
    const r = await this.req(method, path, body, timeoutMs);
    if (r.status >= 400) throw Api.fromResponse(r);
    return r.body;
  }
}
