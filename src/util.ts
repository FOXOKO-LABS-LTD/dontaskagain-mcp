import crypto from 'node:crypto';

export function uuid(): string { return crypto.randomUUID(); }

/** An error with a stable code; its message is always our own text (never server text, never file contents). */
export class E2EError extends Error {
  constructor(public code: string, message: string, public detail?: any) { super(message); }
}

/** Canonical JSON (sorted keys) for local idempotency. */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  const o = v as Record<string, unknown>;
  return '{' + Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(o[k])).join(',') + '}';
}

/** Final statuses — only ever set by a status signed by the wallet. */
export const FINAL = new Set(['rejected', 'expired', 'cancelled', 'confirmed', 'failed']);
export const isFinal = (s: string) => FINAL.has(s);
/** Shown (never stored) when expires_at passed without a status from the wallet: the outcome is not known. */
export const UNKNOWN = 'unknown';

const RANK: Record<string, number> = { pending: 0, signed: 1, broadcast: 2 };
/** Order of statuses: a status never moves back (pending < signed < broadcast < final). The wallet never signs on its own (0.1.2): there is no auto_signed. */
export const statusRank = (s: string) => (isFinal(s) ? 3 : RANK[s] ?? 0);

export function reached(until: string, initial: string, st: string): boolean {
  if (until === 'change') return st !== initial;
  if (st === UNKNOWN) return true;
  if (until === 'signed') return isFinal(st) || st === 'signed' || st === 'broadcast';
  return isFinal(st);
}

export function intArg(a: Record<string, any>, k: string, def: number, lo: number, hi: number): number {
  const v = a[k];
  if (v === undefined || v === null || v === '') return def;
  const n = typeof v === 'number' ? Math.trunc(v) : parseInt(String(v), 10);
  if (!Number.isFinite(n)) return def;
  return Math.max(lo, Math.min(hi, n));
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A plain object without a prototype (keys like "__proto__" are ordinary keys). */
export function dict<T>(src?: Record<string, T> | null): Record<string, T> {
  const o = Object.create(null) as Record<string, T>;
  if (src && typeof src === 'object') for (const k of Object.keys(src)) o[k] = src[k];
  return o;
}

/**
 * Text that came from the Signer operator (not signed by the wallet): control and format characters removed,
 * whitespace collapsed, bounded. It is data for the model to look at, never an instruction.
 */
export function untrusted(s: unknown, max = 120): string | undefined {
  if (s === undefined || s === null) return undefined;
  let t = String(s).replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\u2028\u2029]+/gu, ' ').replace(/\s+/g, ' ').trim();
  if (!t) return undefined;
  if (t.length > max) t = t.slice(0, max) + '…';
  return t;
}

/** A server error code: ^[A-Z0-9_]{1,40}$ or HTTP_<status>. */
export function safeCode(code: unknown, status: number): string {
  const c = typeof code === 'string' ? code : '';
  return /^[A-Z0-9_]{1,40}$/.test(c) ? c : `HTTP_${status || 0}`;
}

/** TRON base58 addresses are case-sensitive; EVM hex addresses are not (EIP-55 is only a checksum). */
export function sameAddress(a: unknown, b: unknown): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || !a || !b) return false;
  const hex = /^0x[0-9a-fA-F]{40}$/;
  if (hex.test(a) && hex.test(b)) return a.toLowerCase() === b.toLowerCase();
  return a === b;
}
