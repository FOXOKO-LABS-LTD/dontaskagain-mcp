// Local checks of an intent before it goes to the wallet (0.1.5): network served, asset listed, amount precision,
// recipient address format (TRON base58check, EVM hex with the EIP-55 checksum when mixed case). The wallet checks
// all of it again when it opens the request; these checks only spare the human a window that would fail anyway.
// Error codes are the wallet's own: UNSUPPORTED_NETWORK, UNSUPPORTED_ASSET, BAD_AMOUNT, INVALID_ADDRESS, SELF_TRANSFER.
import crypto from 'node:crypto';
import { E2EError } from './util.js';

/** Networks the wallet serves (others of networks_trusted are listed but not served). */
export const SERVED_NETWORKS = ['tron', 'evm:1', 'evm:42161', 'evm:10', 'evm:137', 'evm:8453'] as const;
const NET_NAMES: Record<string, string> = { tron: 'TRON', 'evm:1': 'Ethereum', 'evm:42161': 'Arbitrum', 'evm:10': 'Optimism', 'evm:137': 'Polygon', 'evm:8453': 'Base' };

/** Assets of a transfer per network and their decimals (the wallet's token list). */
export const ASSETS: Record<string, Record<string, number>> = {
  tron: { TRX: 6, USDT: 6 },
  'evm:1': { ETH: 18, USDT: 6, USDC: 6 },
  'evm:42161': { ETH: 18, USDC: 6, USDT: 6 },
  'evm:10': { ETH: 18, USDC: 6, USDT: 6 },
  'evm:137': { POL: 18, USDC: 6, USDT: 6 },
  'evm:8453': { ETH: 18, USDC: 6 },
};
const CCTP = ['evm:1', 'evm:42161', 'evm:10', 'evm:137', 'evm:8453'];
const REFUEL_TO = ['evm:8453', 'evm:10', 'evm:42161'];

const served = (n: string) => (SERVED_NETWORKS as readonly string[]).includes(n);
const servedList = () => SERVED_NETWORKS.map((n) => `${n} (${NET_NAMES[n]})`).join(', ');

function unsupported(network: string, field: string): never {
  throw new E2EError('UNSUPPORTED_NETWORK', `network ${JSON.stringify(network.slice(0, 40))} is not served by the wallet; served: ${servedList()}`, { field, served: [...SERVED_NETWORKS] });
}

// ---- amounts ----

/** Decimal string → integer in the smallest unit; null when it has more fraction digits than `decimals`. */
export function toUnits(amount: string, decimals: number): bigint | null {
  const m = /^(\d{1,40})(?:\.(\d{1,40}))?$/.exec(amount);
  if (!m) return null;
  const frac = m[2] ?? '';
  if (frac.length > decimals) return null;
  return BigInt(m[1] + frac.padEnd(decimals, '0'));
}

function checkAmount(field: string, amount: unknown, decimals: number, asset: string): bigint {
  const raw = typeof amount === 'string' ? toUnits(amount, decimals) : null;
  if (raw === null) throw new E2EError('BAD_AMOUNT', `${field}: ${asset} has ${decimals} decimal places at most (got ${JSON.stringify(String(amount).slice(0, 50))})`, { field, decimals, asset });
  if (raw <= 0n) throw new E2EError('BAD_AMOUNT', `${field} must be greater than zero`, { field });
  return raw;
}

// ---- addresses ----

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58decode(s: string): Buffer | null {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const body = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  return Buffer.concat([Buffer.alloc(zeros), body]);
}
const sha256 = (b: Uint8Array) => crypto.createHash('sha256').update(b).digest();

/** TRON base58check: 25 bytes, 0x41 prefix, double-SHA256 checksum. */
export function isTronAddress(a: string): boolean {
  if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a)) return false;
  const b = base58decode(a);
  if (!b || b.length !== 25 || b[0] !== 0x41) return false;
  return sha256(sha256(b.subarray(0, 21))).subarray(0, 4).equals(b.subarray(21));
}

// Keccak-256 (the pre-NIST padding Ethereum uses; node:crypto has only SHA3-256).
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const M64 = (1n << 64n) - 1n;
const rotl = (x: bigint, n: number) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64);
function keccakF(s: bigint[]): void {
  for (let round = 0; round < 24; round++) {
    const c = [0, 1, 2, 3, 4].map((x) => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) s[x + y] ^= d;
    }
    const b = new Array<bigint>(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], ROT[x + 5 * y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & M64 & b[((x + 2) % 5) + 5 * y]);
    s[0] ^= RC[round];
  }
}
export function keccak256(data: Uint8Array): Buffer {
  const rate = 136;
  const padded = Buffer.alloc(Math.floor(data.length / rate) * rate + rate);
  padded.set(data);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const s = new Array<bigint>(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) s[i] ^= padded.readBigUInt64LE(off + i * 8);
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(s[i], i * 8);
  return out;
}

/** EIP-55 checksummed form of a 0x + 40 hex address. */
export function toChecksumAddress(a: string): string {
  const low = a.slice(2).toLowerCase();
  const h = keccak256(Buffer.from(low, 'ascii')).toString('hex');
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? low[i].toUpperCase() : low[i];
  return out;
}

/** 0x + 40 hex; when the letters are of mixed case, the EIP-55 checksum must match. */
export function isEvmAddress(a: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) return false;
  const hex = a.slice(2);
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return true;
  return toChecksumAddress(a) === a;
}

function checkTo(network: string, to: unknown): string {
  const t = typeof to === 'string' ? to.trim() : '';
  if (network === 'tron') {
    if (!isTronAddress(t)) {
      throw new E2EError('INVALID_ADDRESS', /^0x[0-9a-fA-F]{40}$/.test(t)
        ? 'to is an EVM address, the network is tron: a TRON address is base58 T… (34 characters)'
        : 'to is not a valid TRON address (base58check T…, 34 characters, case-sensitive)', { field: 'to', network });
    }
    return t;
  }
  if (!isEvmAddress(t)) {
    throw new E2EError('INVALID_ADDRESS', /^0x[0-9a-fA-F]{40}$/.test(t)
      ? 'to has a wrong EIP-55 checksum (mixed case): a typo or a changed character — ask the human for the exact address, do not change its case yourself'
      : /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(t) ? `to is a TRON address, the network is ${network}: an EVM address is 0x + 40 hex`
        : 'to is not an EVM address (0x + 40 hex characters)', { field: 'to', network });
  }
  return t;
}

/** The asset symbol as the wallet lists it (case-insensitive input), or UNSUPPORTED_ASSET. */
function checkAsset(network: string, asset: unknown, field = 'asset'): string {
  const sym = String(asset ?? '').toUpperCase();
  const list = ASSETS[network];
  if (!list || list[sym] === undefined) {
    throw new E2EError('UNSUPPORTED_ASSET', `asset ${JSON.stringify(String(asset ?? '').slice(0, 20))} is not in the token list of ${network}; listed: ${Object.keys(list ?? {}).join(', ')}`, { field, listed: Object.keys(list ?? {}) });
  }
  return sym;
}

const family = (n: string) => (n === 'tron' ? 'tron' : 'evm');

/** What the balance check needs: the network, asset and amount the account gives away. */
export interface Spend { network: string; asset: string; amount: string; raw: bigint; decimals: number }

/**
 * Checks the intent `body` (already normalized by Agent.check) against the wallet's served networks and token list and
 * the recipient format. `account` is the bound account of the view (addresses), if known. Throws E2EError with the
 * wallet's code; returns what the account spends (for the balance warning of wallet_preview).
 */
export function validateIntent(type: string, body: Record<string, any>, account: any | null): Spend | null {
  const addrs: Record<string, unknown> | null = account && account.addresses && typeof account.addresses === 'object' ? account.addresses : null;
  const needAddress = (network: string) => {
    if (addrs && typeof addrs[family(network)] !== 'string') {
      throw new E2EError('UNSUPPORTED_NETWORK', `account ${String(account.name ?? account.id).slice(0, 40)} has no ${family(network) === 'tron' ? 'TRON' : 'EVM'} address`, { field: 'network' });
    }
  };
  if (type === 'transfer') {
    const network = String(body.network ?? '');
    if (!network) throw new E2EError('UNSUPPORTED_NETWORK', `network is required; served: ${servedList()}`, { field: 'network', served: [...SERVED_NETWORKS] });
    if (!served(network)) unsupported(network, 'network');
    needAddress(network);
    const asset = checkAsset(network, body.asset);
    body.asset = asset; // the wallet's symbol (EVM token lists are matched exactly)
    const decimals = ASSETS[network][asset];
    const raw = checkAmount('amount', body.amount, decimals, asset);
    const to = checkTo(network, body.to);
    const own = addrs?.[family(network)];
    if (typeof own === 'string' && (network === 'tron' ? own === to : own.toLowerCase() === to.toLowerCase())) {
      throw new E2EError('SELF_TRANSFER', 'to is the account\'s own address', { field: 'to' });
    }
    return { network, asset, amount: String(body.amount), raw, decimals };
  }
  if (type === 'swap') {
    const network = String(body.network ?? 'tron');
    if (network !== 'tron') throw new E2EError('UNSUPPORTED_NETWORK', `swap is served on tron only (got ${JSON.stringify(network.slice(0, 40))})`, { field: 'network', served: ['tron'] });
    needAddress('tron');
    const ai = String(body.asset_in ?? '').toUpperCase(), ao = String(body.asset_out ?? '').toUpperCase();
    if (!['TRX', 'USDT'].includes(ai) || !['TRX', 'USDT'].includes(ao)) throw new E2EError('UNSUPPORTED_ASSET', 'swap is TRX ↔ USDT only', { field: 'asset_in' });
    if (ai === ao) throw new E2EError('SAME_ASSET', 'asset_in and asset_out are the same', { field: 'asset_out' });
    const raw = checkAmount('amount_in', body.amount_in, 6, ai);
    return { network, asset: ai, amount: String(body.amount_in), raw, decimals: 6 };
  }
  if (type === 'bridge') {
    const from = String(body.from_network ?? body.network ?? ''), to = String(body.to_network ?? '');
    if (!from || !to) throw new E2EError('UNSUPPORTED_NETWORK', `from_network and to_network are required; USDC bridge networks: ${CCTP.join(', ')}`, { field: from ? 'to_network' : 'from_network', served: CCTP });
    for (const [n, f] of [[from, 'from_network'], [to, 'to_network']]) {
      if (!CCTP.includes(n)) throw new E2EError('UNSUPPORTED_NETWORK', `network ${JSON.stringify(n.slice(0, 40))} has no USDC bridge in the wallet; bridge networks: ${CCTP.join(', ')}`, { field: f, served: CCTP });
    }
    if (from === to) throw new E2EError('SAME_NETWORK', 'from_network and to_network are the same', { field: 'to_network' });
    if (body.asset !== undefined && String(body.asset).toUpperCase() !== 'USDC') throw new E2EError('UNSUPPORTED_ASSET', 'the bridge moves USDC only', { field: 'asset' });
    needAddress(from);
    const raw = checkAmount('amount', body.amount, 6, 'USDC');
    return { network: from, asset: 'USDC', amount: String(body.amount), raw, decimals: 6 };
  }
  if (type === 'refuel') {
    const from = String(body.from_network ?? body.network ?? 'evm:1'), to = String(body.to_network ?? '');
    if (from !== 'evm:1') throw new E2EError('UNSUPPORTED_NETWORK', 'refuel goes from evm:1 (Ethereum) only', { field: 'from_network', served: ['evm:1'] });
    if (!REFUEL_TO.includes(to)) throw new E2EError('UNSUPPORTED_NETWORK', `refuel goes to ${REFUEL_TO.join(', ')} only (got ${JSON.stringify(to.slice(0, 40))})`, { field: 'to_network', served: REFUEL_TO });
    needAddress(from);
    const raw = checkAmount('amount_eth', body.amount_eth, 18, 'ETH');
    return { network: from, asset: 'ETH', amount: String(body.amount_eth), raw, decimals: 18 };
  }
  return null;
}

/**
 * Balance warning of wallet_preview: the balance reported by the Signer (unverified) is lower than what the intent
 * spends. Never a refusal — the Signer's numbers are not signed by the wallet. Gas / TRON resources are not counted.
 */
export function balanceWarning(spend: Spend | null, balances: Record<string, any> | undefined, accountId: string | undefined): Record<string, any> | null {
  if (!spend || !balances || !accountId) return null;
  const have = balances[accountId]?.[spend.network]?.[spend.asset];
  if (typeof have !== 'string') return null;
  const haveRaw = toUnits(have, spend.decimals) ?? toUnits(have.replace(/(\.\d*?)0+$/, '$1').replace(/\.$/, ''), spend.decimals);
  if (haveRaw === null || haveRaw >= spend.raw) return null;
  return {
    code: 'INSUFFICIENT_BALANCE', network: spend.network, asset: spend.asset, need: spend.amount, have_unverified: have,
    message: `the Signer reports ${have} ${spend.asset} on ${spend.network}, the request needs ${spend.amount} (unverified: the wallet checks the real balance when it signs)`,
  };
}
