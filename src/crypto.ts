// E2E envelope crypto ("daa-e2e-1"). node:crypto only.
// Ed25519 (sender signature) + X25519 ephemeral-static (key agreement) + HKDF-SHA256 + AES-256-GCM.
import crypto from 'node:crypto';

export const V = 'daa-e2e-1';

export const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
export function unb64u(s: string, len?: number): Buffer {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('E2E_BAD_ENVELOPE: not base64url');
  const b = Buffer.from(s, 'base64url');
  if (len !== undefined && b.length !== len) throw new Error(`E2E_BAD_ENVELOPE: expected ${len} bytes`);
  return b;
}
const sha256 = (...p: (Uint8Array | string)[]): Buffer => {
  const h = crypto.createHash('sha256');
  for (const x of p) h.update(typeof x === 'string' ? Buffer.from(x, 'utf8') : x);
  return h.digest();
};

const PKCS8 = { x25519: '302e020100300506032b656e04220420', ed25519: '302e020100300506032b657004220420' } as const;
const SPKI = { x25519: '302a300506032b656e032100', ed25519: '302a300506032b6570032100' } as const;
type Kind = keyof typeof PKCS8;
const privKey = (k: Kind, raw: Uint8Array) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from(PKCS8[k], 'hex'), raw]), format: 'der', type: 'pkcs8' });
const pubKey = (k: Kind, raw: Uint8Array) => crypto.createPublicKey({ key: Buffer.concat([Buffer.from(SPKI[k], 'hex'), raw]), format: 'der', type: 'spki' });
const rawPub = (k: Kind, priv: Uint8Array): Buffer => crypto.createPublicKey(privKey(k, priv)).export({ format: 'der', type: 'spki' }).subarray(-32);

export const x25519Pub = (priv: Uint8Array) => rawPub('x25519', priv);
export const ed25519Pub = (priv: Uint8Array) => rawPub('ed25519', priv);

export interface KeyPairs { sig_priv: Buffer; kex_priv: Buffer; sig: Buffer; kex: Buffer }
export function generateKeys(): KeyPairs {
  const sig_priv = crypto.randomBytes(32), kex_priv = crypto.randomBytes(32);
  return { sig_priv, kex_priv, sig: ed25519Pub(sig_priv), kex: x25519Pub(kex_priv) };
}

/** base32 (RFC 4648, no padding) of sha256("daa-fp-1\n" || sig || kex)[0:15], 6 groups of 4. */
export function fingerprint(sigPub: Uint8Array, kexPub: Uint8Array): string {
  const h = sha256('daa-fp-1\n', sigPub, kexPub).subarray(0, 15);
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, val = 0, out = '';
  for (const byte of h) { val = ((val << 8) | byte) & 0xffff; bits += 8; while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  return out.match(/.{4}/g)!.join('-');
}
export const keyId = (kexPub: Uint8Array) => b64u(sha256(kexPub).subarray(0, 8));
export const bundle = (sigPub: Uint8Array, kexPub: Uint8Array) => `${b64u(sigPub)}.${b64u(kexPub)}`;
export function parseBundle(s: string): { sig: Buffer; kex: Buffer } {
  const p = String(s ?? '').trim().split('.');
  if (p.length !== 2) throw new Error('E2E_BAD_KEY: a key bundle is "<ed25519 b64url>.<x25519 b64url>"');
  return { sig: unb64u(p[0], 32), kex: unb64u(p[1], 32) };
}

export interface Envelope {
  v: string; id: string; wallet_id: string; from: string; to: string; at: string;
  epk: string; rk: string; n: string; ct: string; sig: string;
}
type Header = Pick<Envelope, 'id' | 'wallet_id' | 'from' | 'to' | 'at' | 'epk' | 'rk'>;

export const aad = (h: Header) => [V, h.id, h.wallet_id, h.from, h.to, h.at, h.epk, h.rk].join('\n');
export const sigMessage = (h: Header & { n: string }, ct: Uint8Array) => `sig:${aad(h)}\n${h.n}\n${b64u(sha256(ct))}`;

function kdf(shared: Buffer, epk: Uint8Array, rcptKex: Uint8Array): Buffer {
  if (shared.every((x) => x === 0)) throw new Error('E2E_BAD_KEY: all-zero shared secret');
  return Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([epk, rcptKex]), Buffer.from(`${V} aes-256-gcm key`), 32));
}

export interface SealArgs {
  id?: string; wallet_id: string; from: string; to: string; at?: string; payload: unknown;
  senderSigPriv: Uint8Array; recipientKexPub: Uint8Array;
  eph?: Uint8Array; nonce?: Uint8Array; // vectors only
}
export const newEnvelopeId = () => 'env_' + b64u(crypto.randomBytes(16));
export const nowSec = (d = new Date()) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

export function seal(a: SealArgs): Envelope {
  const eph = a.eph ?? crypto.randomBytes(32), nonce = a.nonce ?? crypto.randomBytes(12);
  const epk = x25519Pub(eph);
  const h = { id: a.id ?? newEnvelopeId(), wallet_id: a.wallet_id, from: a.from, to: a.to, at: a.at ?? nowSec(), epk: b64u(epk), rk: keyId(a.recipientKexPub), n: b64u(nonce) };
  const shared = crypto.diffieHellman({ privateKey: privKey('x25519', eph), publicKey: pubKey('x25519', a.recipientKexPub) });
  const key = kdf(shared, epk, a.recipientKexPub);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(Buffer.from(aad(h)));
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(a.payload), 'utf8')), c.final(), c.getAuthTag()]);
  const sig = crypto.sign(null, Buffer.from(sigMessage(h, ct)), privKey('ed25519', a.senderSigPriv));
  return { v: V, ...h, ct: b64u(ct), sig: b64u(sig) };
}

const FIELDS = ['v', 'id', 'wallet_id', 'from', 'to', 'at', 'epk', 'rk', 'n', 'ct', 'sig'] as const;
export function checkShape(env: any): asserts env is Envelope {
  if (!env || typeof env !== 'object') throw new Error('E2E_BAD_ENVELOPE: not an object');
  for (const f of FIELDS) if (typeof env[f] !== 'string') throw new Error(`E2E_BAD_ENVELOPE: ${f}`);
  if (env.v !== V) throw new Error('E2E_VERSION: ' + env.v);
}

/** The sender's signature (checked before decrypting). */
export function verify(env: Envelope, senderSigPub: Uint8Array): boolean {
  try {
    checkShape(env);
    return crypto.verify(null, Buffer.from(sigMessage(env, unb64u(env.ct))), pubKey('ed25519', senderSigPub), unb64u(env.sig, 64));
  } catch { return false; }
}

/** verify → key id → decrypt. Throws E2E_BAD_SIGNATURE / E2E_WRONG_KEY / E2E_DECRYPT. */
export function open<T = any>(env: Envelope, o: { senderSigPub: Uint8Array; recipientKexPriv: Uint8Array }): T {
  checkShape(env);
  if (!verify(env, o.senderSigPub)) throw new Error('E2E_BAD_SIGNATURE');
  return decryptOnly<T>(env, o.recipientKexPriv);
}

/** Decrypt without the signature check — only for "pair", whose key is inside (the caller verifies after). */
export function decryptOnly<T = any>(env: Envelope, recipientKexPriv: Uint8Array): T {
  const rk = x25519Pub(recipientKexPriv);
  if (env.rk !== keyId(rk)) throw new Error('E2E_WRONG_KEY');
  const epk = unb64u(env.epk, 32);
  const shared = crypto.diffieHellman({ privateKey: privKey('x25519', recipientKexPriv), publicKey: pubKey('x25519', epk) });
  const key = kdf(shared, epk, rk);
  const ct = unb64u(env.ct);
  if (ct.length < 16) throw new Error('E2E_DECRYPT');
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, unb64u(env.n, 12));
    d.setAAD(Buffer.from(aad(env)));
    d.setAuthTag(ct.subarray(ct.length - 16));
    return JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8'));
  } catch { throw new Error('E2E_DECRYPT'); }
}

/** b64u(HMAC-SHA256(code, "daa-pair-1\n" + wallet_id + "\n" + agent_id + "\n" + sig + "\n" + kex + "\n" + wallet_fp)). */
export function pairProof(codeB64u: string, f: { wallet_id: string; agent_id: string; sig: string; kex: string; wallet_fp: string }): string {
  return b64u(crypto.createHmac('sha256', unb64u(codeB64u)).update(['daa-pair-1', f.wallet_id, f.agent_id, f.sig, f.kex, f.wallet_fp].join('\n')).digest());
}
export const sha256hex = (s: string) => sha256(s).toString('hex');
export const randomB64u = (n: number) => b64u(crypto.randomBytes(n));
