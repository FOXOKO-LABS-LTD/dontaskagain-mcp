// Agent key file and local state ($DAA_HOME, default ~/.dontaskagain). Key: agents/<agent_id>.json, mode 0600,
// folder 0700. State (requests, inbox cursor, seen envelope ids): state/<agent_id>.json. Several processes of one
// agent (one per Claude Code session) share these files: every change is read-modify-write under the lock file
// state/<agent_id>.lock. Permissions are enforced, not advised: a key or state file readable by
// others, a folder writable by others or owned by another user → E2E_KEY_FILE_PERMS. Damaged files are reported
// without their contents.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { b64u, bundle, fingerprint, generateKeys, unb64u, type Envelope, type KeyPairs } from './crypto.js';
import { dict, E2EError } from './util.js';

export interface KeyFile {
  v: 1;
  agent_id: string;
  created_at: string;
  keys: { sig_priv: string; kex_priv: string; sig: string; kex: string };
  fp: string;
  /** wallet_id_source: 'config' (DAA_WALLET_ID) or 'server' (GET /v1/e2e/info, confirmed only by "paired"). */
  wallet: { bundle: string; fp: string; wallet_id?: string; wallet_id_source?: 'config' | 'server' };
  pair: { code_hash: string; sent_at?: string; env_id?: string; env?: Envelope } | null;
  paired: { at: string; name?: string; wallet_fp: string; agent_fp: string } | null;
}

const POSIX = process.platform !== 'win32';
const myUid = () => (typeof process.getuid === 'function' ? process.getuid() : -1);

export function expandHome(p: string): string {
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

export function daaHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.DAA_HOME && env.DAA_HOME.trim() ? path.resolve(expandHome(env.DAA_HOME.trim())) : path.join(os.homedir(), '.dontaskagain');
}

const permsError = (msg: string) => new E2EError('E2E_KEY_FILE_PERMS', msg);
const mode8 = (m: number) => (m & 0o777).toString(8);

/** DAA_HOME: created 0700 if missing; otherwise must be ours and not writable by group/others. */
export function checkHome(home: string) {
  if (!fs.existsSync(home)) { fs.mkdirSync(home, { recursive: true, mode: 0o700 }); }
  if (!POSIX) return;
  const st = fs.statSync(home);
  if (!st.isDirectory()) throw permsError(`${home} (DAA_HOME) is not a folder`);
  if (st.uid !== myUid()) throw permsError(`${home} (DAA_HOME) belongs to another user (uid ${st.uid}); use a folder of your own`);
  if (st.mode & 0o022) throw permsError(`${home} (DAA_HOME) is writable by other users (mode ${mode8(st.mode)}) — run: chmod 700 ${home}`);
}

/** agents/ and state/: 0700, ours, not a symlink. A folder we own is tightened; a failing chmod is an error. */
function ensureDir(dir: string) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!POSIX) return;
  let st = fs.lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw permsError(`${dir} is not a plain folder (symlink?); refusing to keep keys there`);
  if (st.uid !== myUid()) throw permsError(`${dir} belongs to another user (uid ${st.uid}); refusing to keep keys there`);
  if (st.mode & 0o077) {
    try { fs.chmodSync(dir, 0o700); } catch { throw permsError(`${dir} has mode ${mode8(st.mode)} and chmod 700 failed`); }
    st = fs.lstatSync(dir);
    if (st.mode & 0o077) throw permsError(`${dir} has mode ${mode8(st.mode)}, expected 700`);
  }
}

/** A file we read secrets from: a regular file of ours, no access for group/others. */
function checkFile(file: string, what: string) {
  if (!POSIX) return;
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile()) throw permsError(`${what} ${file} is not a regular file (symlink?)`);
  if (st.uid !== myUid()) throw permsError(`${what} ${file} belongs to another user (uid ${st.uid})`);
  if (st.mode & 0o077) throw permsError(`${what} ${file} has mode ${mode8(st.mode)}, expected 600 — anyone who could read it may have the key; run: chmod 600 ${file}`);
}

function tmpName(file: string) { return `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`; }

function writeTmp(file: string, data: string, mode: number): string {
  ensureDir(path.dirname(file));
  const tmp = tmpName(file);
  const fd = fs.openSync(tmp, 'wx', mode);
  try {
    fs.fchmodSync(fd, mode);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } catch (e) { fs.closeSync(fd); try { fs.unlinkSync(tmp); } catch { /* gone */ } throw e; }
  fs.closeSync(fd);
  return tmp;
}

/** Atomic write with the given mode (temp file in the same folder, then rename). */
export function writeFileSecure(file: string, data: string, mode = 0o600) {
  const tmp = writeTmp(file, data, mode);
  try { fs.renameSync(tmp, file); } catch (e) { try { fs.unlinkSync(tmp); } catch { /* gone */ } throw e; }
}

/** Creates the file only if it does not exist (complete content or nothing). false = it already existed. */
export function createFileExclusive(file: string, data: string, mode = 0o600): boolean {
  const tmp = writeTmp(file, data, mode);
  try { fs.linkSync(tmp, file); return true; }
  catch (e: any) { if (e?.code === 'EEXIST') return false; throw e; }
  finally { try { fs.unlinkSync(tmp); } catch { /* gone */ } }
}

export const keyPath = (home: string, agentId: string) => path.join(home, 'agents', `${agentId}.json`);
export const statePath = (home: string, agentId: string) => path.join(home, 'state', `${agentId}.json`);
export const lockPath = (home: string, agentId: string) => path.join(home, 'state', `${agentId}.lock`);

// ---- lock ----

const LOCK_WAIT_MS = 15_000;
const LOCK_STALE_MS = 30_000;
const held = new Map<string, number>();
const sleepSync = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e: any) { return e?.code === 'EPERM'; }
}

/** A lock left by a crashed process (dead pid) or older than LOCK_STALE_MS (critical sections take milliseconds). */
function breakIfStale(lp: string): void {
  let content: string, st: fs.Stats;
  try { content = fs.readFileSync(lp, 'utf8'); st = fs.statSync(lp); } catch { return; }
  const pid = Number(content.split(' ')[0]);
  const age = Date.now() - st.mtimeMs;
  if (age < LOCK_STALE_MS) {
    if (!Number.isInteger(pid) || pid <= 0) return;           // being written right now
    if (pid !== process.pid && pidAlive(pid)) return;         // a live process holds it
    if (pid === process.pid && held.has(lp)) return;
  }
  const aside = `${lp}.${crypto.randomBytes(6).toString('hex')}.stale`;
  try { fs.renameSync(lp, aside); } catch { return; }
  let moved = '';
  try { moved = fs.readFileSync(aside, 'utf8'); } catch { /* gone */ }
  if (moved !== content) { try { fs.linkSync(aside, lp); } catch { /* someone else locked meanwhile */ } }
  try { fs.unlinkSync(aside); } catch { /* gone */ }
}

/**
 * Runs fn holding state/<agent_id>.lock (exclusive create + pid + time). fn must be synchronous: the lock is held
 * for a read-modify-write of the files, never across network calls. Nested calls in the same process are allowed.
 */
export function withLock<T>(home: string, agentId: string, fn: () => T): T {
  const lp = lockPath(home, agentId);
  const depth = held.get(lp) ?? 0;
  if (depth > 0) { held.set(lp, depth + 1); try { return fn(); } finally { held.set(lp, depth); } }
  ensureDir(path.dirname(lp));
  const token = `${process.pid} ${Date.now()} ${crypto.randomBytes(8).toString('hex')}`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (let i = 0; ; i++) {
    try {
      const fd = fs.openSync(lp, 'wx', 0o600);
      try { fs.writeSync(fd, token); } finally { fs.closeSync(fd); }
      break;
    } catch (e: any) {
      if (e?.code !== 'EEXIST') throw e;
    }
    breakIfStale(lp);
    if (Date.now() > deadline) throw new E2EError('E2E_LOCK_TIMEOUT', `another process of this agent holds ${lp}; if no other dontaskagain-mcp is running, delete that file`);
    sleepSync(Math.min(50, 5 + i * 2));
  }
  held.set(lp, 1);
  try { return fn(); } finally {
    held.delete(lp);
    try { if (fs.readFileSync(lp, 'utf8') === token) fs.unlinkSync(lp); } catch { /* already gone */ }
  }
}

// ---- key file ----

export function newKeyFile(agentId: string, walletBundle: string, walletFp: string): KeyFile {
  const k = generateKeys();
  return {
    v: 1, agent_id: agentId, created_at: new Date().toISOString(),
    keys: { sig_priv: b64u(k.sig_priv), kex_priv: b64u(k.kex_priv), sig: b64u(k.sig), kex: b64u(k.kex) },
    fp: fingerprint(k.sig, k.kex), wallet: { bundle: walletBundle, fp: walletFp }, pair: null, paired: null,
  };
}

function parseJsonFile(file: string, what: string): any {
  let text: string;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e: any) { throw new E2EError('E2E_KEY_FILE', `${what} ${file} cannot be read (${e?.code ?? 'error'})`); }
  try { return JSON.parse(text); } catch { throw new E2EError('E2E_KEY_FILE', `${what} ${file} is damaged (not valid JSON); restore it or reconnect the agent from the wallet`); }
}

/** Reads the key file (null if there is none). Wrong permissions or a damaged file → error without its contents. */
export function readKeyFile(home: string, agentId: string): KeyFile | null {
  const file = keyPath(home, agentId);
  if (!fs.existsSync(file)) return null;
  ensureDir(path.dirname(file));
  checkFile(file, 'key file');
  const kf = parseJsonFile(file, 'key file') as KeyFile;
  if (!kf || kf.v !== 1 || kf.agent_id !== agentId || typeof kf.keys?.sig_priv !== 'string' || typeof kf.keys?.kex_priv !== 'string' || typeof kf.fp !== 'string' || typeof kf.wallet?.bundle !== 'string') {
    throw new E2EError('E2E_KEY_FILE', `key file ${file} is not a key of ${agentId}`);
  }
  return kf;
}

export function saveKeyFile(home: string, kf: KeyFile) { writeFileSecure(keyPath(home, kf.agent_id), JSON.stringify(kf, null, 2) + '\n'); }
/** The first key of an agent: exclusive create. false = another process created it first (read that one). */
export function createKeyFile(home: string, kf: KeyFile): boolean { return createFileExclusive(keyPath(home, kf.agent_id), JSON.stringify(kf, null, 2) + '\n'); }

/** Rotation: the old file is kept as <agent_id>.json.old until the new key is paired (then removed). */
export function retireKeyFile(home: string, agentId: string) {
  const f = keyPath(home, agentId);
  if (fs.existsSync(f)) { fs.renameSync(f, f + '.old'); fs.chmodSync(f + '.old', 0o600); }
}
export function removeRetiredKeyFile(home: string, agentId: string): boolean {
  const f = keyPath(home, agentId) + '.old';
  try { fs.unlinkSync(f); return true; } catch { return false; }
}

export function keysOf(kf: KeyFile): KeyPairs {
  return { sig_priv: unb64u(kf.keys.sig_priv, 32), kex_priv: unb64u(kf.keys.kex_priv, 32), sig: unb64u(kf.keys.sig, 32), kex: unb64u(kf.keys.kex, 32) };
}
export const agentBundle = (kf: KeyFile) => bundle(unb64u(kf.keys.sig), unb64u(kf.keys.kex));

// ---- state ----
export interface LocalRequest {
  request: Record<string, any>;     // the request object (local until the wallet's first status)
  body_hash: string;                // canonical body for local idempotency
  env_id: string;
  sent_at: string;
  events: { at: string; event: string; status?: string; seq?: number }[];
  cancel_sent_at?: string;
}
export interface State {
  v: 1;
  cursor: number;                   // last seq processed
  requests: Record<string, LocalRequest>;
  by_client_id: Record<string, string>;
  view?: { version: number; payload: any; at: string };
  seen?: Record<string, number>;    // envelope id → when accepted (ms); replays are dropped
}
export const SEEN_TTL_MS = 8 * 86400_000;
const SEEN_MAX = 20_000;

export const emptyState = (): State => ({ v: 1, cursor: 0, requests: dict(), by_client_id: dict(), seen: dict() });

export function readState(home: string, agentId: string): State {
  const f = statePath(home, agentId);
  if (!fs.existsSync(f)) return emptyState();
  checkFile(f, 'state file');
  const s = parseJsonFile(f, 'state file');
  if (!s || typeof s !== 'object') throw new E2EError('E2E_KEY_FILE', `state file ${f} is damaged`);
  return {
    v: 1, cursor: Number.isSafeInteger(s.cursor) && s.cursor >= 0 ? s.cursor : 0,
    requests: dict(s.requests), by_client_id: dict(s.by_client_id), seen: dict(s.seen),
    ...(s.view ? { view: s.view } : {}),
  };
}

export function saveState(home: string, agentId: string, s: State) {
  // keep the newest 2 000 requests
  const ids = Object.keys(s.requests);
  if (ids.length > 2000) {
    ids.sort((a, b) => Date.parse(s.requests[a].sent_at) - Date.parse(s.requests[b].sent_at));
    for (const id of ids.slice(0, ids.length - 2000)) {
      const crid = s.requests[id].request.client_request_id;
      if (crid && s.by_client_id[crid] === id) delete s.by_client_id[crid];
      delete s.requests[id];
    }
  }
  // envelope ids: 8 days, at most SEEN_MAX
  if (s.seen) {
    const now = Date.now();
    for (const k of Object.keys(s.seen)) if (!(now - s.seen[k] < SEEN_TTL_MS)) delete s.seen[k];
    const keys = Object.keys(s.seen);
    if (keys.length > SEEN_MAX) { keys.sort((a, b) => s.seen![a] - s.seen![b]); for (const k of keys.slice(0, keys.length - SEEN_MAX)) delete s.seen[k]; }
  }
  writeFileSecure(statePath(home, agentId), JSON.stringify(s) + '\n');
}

// ---- config file (DAA_CONFIG): secrets out of the command line ----

export const CONFIG_KEYS = ['DAA_URL', 'DAA_TOKEN', 'DAA_WALLET', 'DAA_WALLET_ID', 'DAA_PAIR', 'DAA_HOME'] as const;

/** KEY=VALUE lines (# comments, optional "export ", optional quotes). Must be ours with mode 600. */
export function readConfigFile(file: string): Record<string, string> {
  const f = path.resolve(expandHome(file));
  if (!fs.existsSync(f)) throw new E2EError('E2E_NOT_CONFIGURED', `DAA_CONFIG: ${f} does not exist`);
  if (POSIX) {
    const st = fs.statSync(f);
    if (!st.isFile()) throw new E2EError('E2E_NOT_CONFIGURED', `DAA_CONFIG: ${f} is not a file`);
    if (st.uid !== myUid()) throw new E2EError('E2E_CONFIG_PERMS', `DAA_CONFIG: ${f} belongs to another user (uid ${st.uid})`);
    if (st.mode & 0o077) throw new E2EError('E2E_CONFIG_PERMS', `DAA_CONFIG: ${f} has mode ${mode8(st.mode)}, expected 600 — it holds the agent token; run: chmod 600 ${f}`);
    if (st.size > 16384) throw new E2EError('E2E_NOT_CONFIGURED', `DAA_CONFIG: ${f} is too large`);
  }
  const out: Record<string, string> = {};
  const lines = fs.readFileSync(f, 'utf8').split(/\r?\n/);
  lines.forEach((line, i) => {
    const l = line.trim();
    if (!l || l.startsWith('#')) return;
    const m = /^(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$/.exec(l);
    if (!m) throw new E2EError('E2E_NOT_CONFIGURED', `DAA_CONFIG: ${f} line ${i + 1} is not KEY=VALUE`);
    let v = m[2].trim();
    if (v.length >= 2 && ((v[0] === '"' && v.endsWith('"')) || (v[0] === "'" && v.endsWith("'")))) v = v.slice(1, -1);
    if ((CONFIG_KEYS as readonly string[]).includes(m[1])) out[m[1]] = v;
  });
  return out;
}
