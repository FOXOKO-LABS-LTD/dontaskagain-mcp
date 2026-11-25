// The agent side of the E2E protocol: key, pairing, sealed requests, inbox of wallet envelopes.
//
// Several processes of one agent may run at once (one per Claude Code session, plus `whoami` / `pair`): they share
// the key file and the state file. Every change is a read-modify-write under the agent's lock file; before answering,
// a process re-reads the files, so a status received by any process is seen by all. Envelope ids are
// remembered and a status never moves back (no replay of an older one).
import { Api, ApiError } from './api.js';
import {
  checkShape, fingerprint, newEnvelopeId, nowSec, open, pairProof, parseBundle, randomB64u, seal, sha256hex,
  type Envelope,
} from './crypto.js';
import {
  agentBundle, checkHome, createKeyFile, daaHome, keyPath, keysOf, newKeyFile, readConfigFile, readKeyFile, readState,
  removeRetiredKeyFile, retireKeyFile, saveKeyFile, saveState, withLock,
  type KeyFile, type LocalRequest, type State,
} from './store.js';
import { canonical, dict, E2EError, isFinal, reached, statusRank, UNKNOWN, untrusted, uuid } from './util.js';
import { validateIntent } from './validate.js';

export { E2EError } from './util.js';

export const VERSION = '0.1.5';
/** Types an E2E request can have (x402_pay is not executed end-to-end: the wallet answers E2E_TYPE_UNSUPPORTED). */
export const TYPES = ['transfer', 'swap', 'bridge', 'refuel'] as const;

export const WALLET_ID_RE = /^wal_[A-Za-z0-9_-]{1,64}$/;
export const REQUEST_ID_RE = /^awr_[A-Za-z0-9_-]{1,64}$/;
const ENV_ID_RE = /^env_[A-Za-z0-9_-]{1,64}$/;
const AT_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?Z$/;

/** Fields a tool call may carry, by type. Protocol fields (t, request_id, created_at, expires_at) are never taken from arguments. */
const COMMON_FIELDS = ['type', 'account', 'network', 'reason', 'expires_in', 'client_request_id', 'metadata'];
export const FIELDS_BY_TYPE: Record<string, string[]> = {
  transfer: ['asset', 'to', 'amount', 'resources'],
  swap: ['asset_in', 'asset_out', 'amount_in', 'slippage_bps', 'resources'],
  bridge: ['from_network', 'to_network', 'asset', 'amount', 'mode', 'delivery'],
  refuel: ['from_network', 'to_network', 'amount_eth'],
};
const TOOL_FIELDS = ['wait_seconds'];
const STRING_FIELDS = ['account', 'network', 'asset', 'to', 'from_network', 'to_network', 'mode', 'delivery', 'asset_in', 'asset_out'];
const AMOUNT_FIELDS = ['amount', 'amount_in', 'amount_eth'];

export interface Config {
  url: string; token: string; walletBundle?: string; walletId?: string; pairCode?: string; home: string;
  log?: (s: string) => void;
}

/** Environment first, then the DAA_CONFIG file (KEY=VALUE, mode 600) — so secrets need not be on the command line. */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const file = env.DAA_CONFIG?.trim() ? readConfigFile(env.DAA_CONFIG.trim()) : {};
  const get = (...keys: string[]) => { for (const k of keys) { const v = env[k]?.trim() || file[k]?.trim(); if (v) return v; } return ''; };
  const home = get('DAA_HOME');
  return {
    url: get('DAA_URL'),
    token: get('DAA_TOKEN'),
    walletBundle: get('DAA_WALLET') || undefined,
    walletId: get('DAA_WALLET_ID') || undefined,
    pairCode: get('DAA_PAIR') || undefined,
    home: daaHome(home ? { DAA_HOME: home } : {}),
  };
}

/** "aw_<agent_id>_<secret>", agent_id = "ag_" + lowercase base32 (core/wallet.go). */
export function agentIdFromToken(tok: string): string {
  const m = /^aw_(ag_[a-z0-9]{1,64})_[A-Za-z0-9]+$/.exec(tok);
  if (!m) throw new E2EError('E2E_BAD_TOKEN', 'DAA_TOKEN must look like aw_ag_<id>_<secret> (copy it from the wallet)');
  return m[1];
}

/** The request as shown: a pending request past expires_at without a wallet status is "unknown", not "expired". */
export function shownRequest(r: Record<string, any>, now = Date.now()): Record<string, any> {
  if (r.status === 'pending' && r.expires_at && Date.parse(r.expires_at) < now) {
    return {
      ...r, status: UNKNOWN,
      e2e: { ...(r.e2e ?? {}), no_status_from_wallet: true },
      note: 'expires_at passed and no status from the wallet reached this agent. The operation may still have happened: do NOT repeat it with a new client_request_id; check wallet_request_status / wallet_history later or ask the human.',
    };
  }
  return r;
}

type Waiter = () => void;

export class Agent {
  readonly agentId: string;
  readonly api: Api;
  kf!: KeyFile;
  state!: State;
  info: { e2e_mode: string | null; wallet_id: string | null } | null = null;
  private syncing: Promise<void> | null = null;
  private waiters = new Set<Waiter>();
  private log: (s: string) => void;
  rotated = false;

  constructor(public cfg: Config) {
    if (!cfg.url) throw new E2EError('E2E_NOT_CONFIGURED', 'DAA_URL (the Signer address from the wallet) is not set');
    if (!cfg.token) throw new E2EError('E2E_NOT_CONFIGURED', 'DAA_TOKEN (the agent token from the wallet) is not set');
    if (cfg.walletId !== undefined && !WALLET_ID_RE.test(cfg.walletId)) throw new E2EError('E2E_NOT_CONFIGURED', 'DAA_WALLET_ID must look like wal_<id>');
    this.agentId = agentIdFromToken(cfg.token);
    this.api = new Api(cfg.url, cfg.token);
    this.log = cfg.log ?? ((s) => process.stderr.write(`dontaskagain-mcp: ${s}\n`));
  }

  /**
   * Loads or creates the key (rotation on a new pairing code of a paired key; wallet key pinning).
   * readOnly (whoami): creates the first key if there is none, otherwise changes nothing.
   */
  init(opts: { readOnly?: boolean } = {}): this {
    const { home, walletBundle, pairCode, walletId } = this.cfg;
    let wb: { sig: Buffer; kex: Buffer } | undefined;
    try { if (walletBundle) wb = parseBundle(walletBundle); } catch { throw new E2EError('E2E_NOT_CONFIGURED', 'DAA_WALLET is not a wallet key ("<sig>.<kex>", copy it from the wallet)'); }
    const wfp = wb ? fingerprint(wb.sig, wb.kex) : undefined;
    const codeHash = pairCode ? sha256hex('daa-pair-code\n' + pairCode) : undefined;
    checkHome(home);
    const kf = withLock(home, this.agentId, () => {
      let kf = readKeyFile(home, this.agentId);
      if (!kf) {
        if (!walletBundle || !wfp) throw new E2EError('E2E_NOT_CONFIGURED', 'DAA_WALLET (the wallet key from the connect command) is not set and there is no key file yet');
        kf = newKeyFile(this.agentId, walletBundle, wfp);
        if (codeHash) kf.pair = { code_hash: codeHash };
        if (walletId) kf.wallet = { ...kf.wallet, wallet_id: walletId, wallet_id_source: 'config' };
        if (!createKeyFile(home, kf)) kf = readKeyFile(home, this.agentId)!; // lost a race (lock-less writer): use the winner's key
        return kf;
      }
      if (opts.readOnly) return kf;
      const before = JSON.stringify(kf);
      const walletChanged = !!walletBundle && walletBundle !== kf.wallet.bundle;
      const newCode = !!codeHash && kf.pair?.code_hash !== codeHash;
      if (walletChanged && !newCode) {
        throw new E2EError('E2E_WALLET_KEY_CHANGED', `DAA_WALLET differs from the wallet key pinned at pairing (${kf.wallet.fp} → ${wfp}). ` +
          'If the human changed the wallet encryption key, reconnect this agent from the wallet (new command with a new DAA_PAIR); otherwise do not trust this configuration.');
      }
      if (newCode && kf.paired) {
        retireKeyFile(home, this.agentId);
        const keepId = kf.wallet.wallet_id_source === 'config' && !walletChanged ? kf.wallet.wallet_id : undefined;
        kf = newKeyFile(this.agentId, walletBundle ?? kf.wallet.bundle, wfp ?? kf.wallet.fp);
        if (keepId) kf.wallet = { ...kf.wallet, wallet_id: keepId, wallet_id_source: 'config' };
        this.rotated = true;
        this.log(`new pairing code: the old key ${this.agentId}.json is kept as .old until the new key is paired, a new key is generated (fingerprint ${kf.fp})`);
      } else if (walletChanged && wfp) {
        kf.wallet = { ...kf.wallet, bundle: walletBundle!, fp: wfp };
      }
      if (codeHash && kf.pair?.code_hash !== codeHash) kf.pair = { code_hash: codeHash };
      if (walletId && kf.wallet.wallet_id !== walletId) {
        if (kf.paired) throw new E2EError('E2E_WALLET_ID_CHANGED', `DAA_WALLET_ID differs from the wallet this key is paired with; reconnect the agent from the wallet`);
        kf.wallet = { ...kf.wallet, wallet_id: walletId, wallet_id_source: 'config' };
        if (kf.pair) kf.pair = { code_hash: kf.pair.code_hash };
      }
      if (JSON.stringify(kf) !== before || this.rotated) saveKeyFile(home, kf);
      return kf;
    });
    this.kf = kf;
    this.state = readState(home, this.agentId);
    return this;
  }

  get keys() { return keysOf(this.kf); }
  get wallet() { return parseBundle(this.kf.wallet.bundle); }
  get paired() { return !!this.kf.paired; }

  /** Re-reads the key and state files (another process of this agent may have changed them). */
  reload(): void {
    const kf = readKeyFile(this.cfg.home, this.agentId);
    if (!kf || kf.fp !== this.kf.fp) {
      throw new E2EError('E2E_KEY_ROTATED', `the key file ${keyPath(this.cfg.home, this.agentId)} was replaced (a new pairing in another process?); restart this MCP server`);
    }
    this.kf = kf;
    this.state = readState(this.cfg.home, this.agentId);
  }
  private reloadQuiet() { try { this.reload(); } catch (e) { if (e instanceof E2EError && e.code === 'E2E_KEY_ROTATED') throw e; } }

  /** Read-modify-write of both files under the lock; fn works on the fresh this.kf / this.state. */
  update<T>(fn: () => T): T {
    return withLock(this.cfg.home, this.agentId, () => {
      this.reload();
      const k0 = JSON.stringify(this.kf), s0 = JSON.stringify(this.state);
      const r = fn();
      if (JSON.stringify(this.kf) !== k0) saveKeyFile(this.cfg.home, this.kf);
      if (JSON.stringify(this.state) !== s0) saveState(this.cfg.home, this.agentId, this.state);
      return r;
    });
  }

  whoami() {
    const spentCode = !!this.kf.paired && !!this.cfg.pairCode && this.kf.pair?.code_hash === sha256hex('daa-pair-code\n' + this.cfg.pairCode);
    const newCode = !!this.cfg.pairCode && this.kf.pair?.code_hash !== sha256hex('daa-pair-code\n' + this.cfg.pairCode);
    return {
      agent_id: this.agentId, agent_fp: this.kf.fp, agent_key: agentBundle(this.kf), wallet_fp: this.kf.wallet.fp,
      wallet_id: this.kf.wallet.wallet_id ?? null, paired: this.kf.paired, pair_pending: !!this.kf.pair && !this.kf.paired,
      key_file: keyPath(this.cfg.home, this.agentId), signer: this.api.base, version: VERSION,
      ...(spentCode ? { hint: 'paired: the pairing code is spent — you can remove DAA_PAIR from the MCP configuration' } : {}),
      ...(newCode ? { hint: 'a new DAA_PAIR is set: the MCP server makes a new key at its next start (whoami changes nothing)' } : {}),
    };
  }

  /**
   * wallet_id: DAA_WALLET_ID (pinned), or GET /v1/e2e/info. A value from the server is checked by form and is only
   * provisional until the wallet's signed "paired" confirms it; before that it is fetched again at every start.
   */
  async walletId(): Promise<string> {
    const pinned = this.kf.wallet.wallet_id;
    if (pinned && this.info) return pinned;
    let info: any;
    try {
      info = await this.api.must('GET', '/v1/e2e/info');
    } catch (e) {
      if (pinned) return pinned;
      throw e;
    }
    const wid = typeof info?.wallet_id === 'string' && WALLET_ID_RE.test(info.wallet_id) ? info.wallet_id : null;
    const mode = typeof info?.e2e_mode === 'string' && ['off', 'on', 'required'].includes(info.e2e_mode) ? info.e2e_mode : null;
    this.info = { e2e_mode: mode, wallet_id: wid };
    if (typeof info?.wallet_key === 'string' && info.wallet_key !== this.kf.wallet.bundle) {
      this.log(`WARNING: the Signer reports a wallet key other than the pinned one (${this.kf.wallet.fp}); the pinned key is used`);
    }
    if (!wid) {
      if (pinned) { this.log('WARNING: the Signer returned no valid wallet_id; the pinned one is used'); return pinned; }
      throw new E2EError('E2E_NO_WALLET', 'the Signer did not return a valid wallet_id (set DAA_WALLET_ID from the wallet\'s connect command)');
    }
    const confirmed = !!pinned && (!!this.kf.paired || this.kf.wallet.wallet_id_source === 'config');
    if (confirmed) {
      if (wid !== pinned) this.log(`WARNING: the Signer reports wallet ${wid}, pinned ${pinned}; the pinned one is used`);
      return pinned!;
    }
    if (wid !== pinned) {
      this.update(() => {
        if (this.kf.paired || this.kf.wallet.wallet_id_source === 'config') return;
        this.kf.wallet = { ...this.kf.wallet, wallet_id: wid, wallet_id_source: 'server' };
        if (this.kf.pair) this.kf.pair = { code_hash: this.kf.pair.code_hash }; // the pair envelope binds wallet_id: make a new one
      });
    }
    return this.kf.wallet.wallet_id!;
  }

  private sealToWallet(payload: unknown, id = newEnvelopeId()): Envelope {
    return seal({ id, wallet_id: this.kf.wallet.wallet_id!, from: this.agentId, to: 'wallet', payload, senderSigPriv: this.keys.sig_priv, recipientKexPub: this.wallet.kex });
  }

  /** Sends the pair envelope once per pairing code (the same bytes on a retry, also from another process). */
  async pairIfNeeded(): Promise<'paired' | 'sent' | 'none'> {
    this.reloadQuiet();
    if (this.kf.paired) return 'paired';
    const code = this.cfg.pairCode;
    if (!this.kf.pair || !code) return 'none';
    await this.walletId();
    const env = this.update(() => {
      if (this.kf.paired || !this.kf.pair) return null;
      const p = this.kf.pair;
      if (!p.env) {
        const k = this.kf.keys;
        const payload = {
          t: 'pair', agent_id: this.agentId, keys: { sig: k.sig, kex: k.kex }, wallet_fp: this.kf.wallet.fp,
          proof: pairProof(code, { wallet_id: this.kf.wallet.wallet_id!, agent_id: this.agentId, sig: k.sig, kex: k.kex, wallet_fp: this.kf.wallet.fp }),
          client: { name: 'dontaskagain-mcp', version: VERSION },
        };
        p.env = this.sealToWallet(payload);
        p.env_id = p.env.id;
      }
      return p.sent_at ? null : p.env;
    });
    if (this.kf.paired) return 'paired';
    if (env) {
      await this.api.must('POST', '/v1/e2e/envelopes', env);
      this.update(() => { if (this.kf.pair && this.kf.pair.env_id === env.id) this.kf.pair.sent_at ??= new Date().toISOString(); });
    }
    return 'sent';
  }

  // ---- inbox ----

  /** One inbox read (long poll up to waitSec), processed and acked; concurrent callers in this process share it. */
  async sync(waitSec = 0): Promise<void> {
    while (this.syncing) await this.syncing.catch(() => {});
    this.syncing = this.syncOnce(waitSec);
    try { await this.syncing; } finally { this.syncing = null; }
  }

  private async syncOnce(waitSec: number): Promise<void> {
    await this.walletId();
    this.reload();
    const w = Math.max(0, Math.min(60, Math.floor(waitSec)));
    const r = await this.api.must('GET', `/v1/e2e/envelopes?after=${this.state.cursor}&limit=100&wait=${w}`, undefined, (w + 30) * 1000);
    const list: { seq: number; envelope: Envelope }[] = Array.isArray(r?.envelopes) ? r.envelopes.slice(0, 100) : [];
    let max = 0;
    let pairedNow = false;
    if (list.length) {
      this.update(() => {
        const wasPaired = !!this.kf.paired;
        for (const it of list) {
          const seq = Number.isSafeInteger(it?.seq) && it.seq >= 0 ? it.seq : undefined;
          if (seq !== undefined && seq > max) max = seq;
          this.accept(it?.envelope, seq);
        }
        if (max > this.state.cursor) this.state.cursor = max;
        pairedNow = !wasPaired && !!this.kf.paired;
      });
      // acked only after the envelopes are written to the shared state file
      if (max > 0) { try { await this.api.req('POST', '/v1/e2e/envelopes/ack', { up_to_seq: max }); } catch { /* the next read acks again */ } }
    }
    if (pairedNow) this.afterPaired();
    for (const w2 of [...this.waiters]) w2();
  }

  private afterPaired() {
    if (removeRetiredKeyFile(this.cfg.home, this.agentId)) this.log('the previous key (.old) is removed: the new key is paired');
    if (this.cfg.pairCode) this.log('paired: the pairing code is spent — you can remove DAA_PAIR from the MCP configuration');
  }

  /** Verifies (pinned wallet key) and applies one envelope; replays and anything else are ignored. Call inside update(). */
  accept(env: any, seq?: number, quietReplay = false): boolean {
    try {
      checkShape(env);
      if (env.from !== 'wallet' || env.to !== this.agentId || env.wallet_id !== this.kf.wallet.wallet_id || !ENV_ID_RE.test(env.id) || !AT_RE.test(env.at)) {
        this.log(`ignored envelope: header is not wallet→${this.agentId} @${this.kf.wallet.wallet_id}`);
        return false;
      }
      this.state.seen ??= dict();
      if (this.state.seen[env.id] !== undefined) {
        if (!quietReplay) this.log(`ignored envelope ${env.id}: already received (replay)`);
        return false;
      }
      const p = open(env, { senderSigPub: this.wallet.sig, recipientKexPriv: this.keys.kex_priv });
      this.state.seen[env.id] = Date.now();
      this.apply(p, seq, env.id);
      return true;
    } catch (e: any) {
      const code = /^E2E_[A-Z_]+/.exec(String(e?.message ?? ''))?.[0] ?? 'E2E_BAD_ENVELOPE';
      this.log(`ignored envelope ${typeof env?.id === 'string' && ENV_ID_RE.test(env.id) ? env.id : '?'}: ${code} (not signed by the pinned wallet key ${this.kf.wallet.fp} or not for this agent)`);
      return false;
    }
  }

  private apply(p: any, seq: number | undefined, envId: string) {
    const at = new Date().toISOString();
    switch (p?.t) {
      case 'paired':
        if (p.agent_fp && p.agent_fp !== this.kf.fp) { this.log(`ignored "paired" for another key ${untrusted(p.agent_fp, 40)} (mine ${this.kf.fp})`); return; }
        if (this.kf.paired) return;
        this.kf.paired = { at, ...(typeof p.name === 'string' ? { name: p.name.slice(0, 100) } : {}), wallet_fp: this.kf.wallet.fp, agent_fp: this.kf.fp };
        // the pair envelope is not needed any more; the code hash stays (a new code = rotation)
        if (this.kf.pair) this.kf.pair = { code_hash: this.kf.pair.code_hash };
        this.log(`paired with the wallet ${this.kf.wallet.fp}`);
        return;
      case 'status': {
        const req = p.request;
        if (!req || typeof req !== 'object' || typeof req.request_id !== 'string' || !REQUEST_ID_RE.test(req.request_id) || typeof req.status !== 'string') return;
        const ev = { at, event: String(p.event ?? 'request.status').slice(0, 40), status: req.status, seq };
        const lr = this.state.requests[req.request_id];
        if (lr) {
          const cur = String(lr.request.status);
          if (isFinal(cur) && req.status !== cur) { this.log(`ignored status ${req.status} for ${req.request_id}: it is already ${cur}`); return; }
          if (statusRank(req.status) < statusRank(cur)) { this.log(`ignored status ${req.status} for ${req.request_id}: it is already ${cur} (statuses do not go back)`); return; }
          lr.request = { ...lr.request, ...req, request_id: lr.request.request_id, e2e: { ...(lr.request.e2e ?? {}), ...(req.e2e ?? {}), delivered_to_wallet: true } };
          lr.events.push(ev);
        } else {
          this.state.requests[req.request_id] = { request: { ...req, e2e: { ...(req.e2e ?? {}), delivered_to_wallet: true } }, body_hash: '', env_id: '', sent_at: typeof req.created_at === 'string' ? req.created_at : at, events: [ev] };
          if (typeof req.client_request_id === 'string' && !(req.client_request_id in this.state.by_client_id)) this.state.by_client_id[req.client_request_id] = req.request_id;
        }
        return;
      }
      case 'error': {
        const ref = String(p.ref ?? '');
        const lr = (REQUEST_ID_RE.test(ref) ? this.state.requests[ref] : undefined) ?? Object.values(this.state.requests).find((r) => r.env_id === ref);
        const code = /^[A-Z0-9_]{1,40}$/.test(String(p.code)) ? String(p.code) : 'E2E_ERROR';
        if (!lr) { this.log(`wallet error ${code} for an unknown reference`); return; }
        if (!isFinal(lr.request.status)) {
          lr.request.status = 'failed';
          lr.request.error = { code, message: untrusted(p.message, 300) ?? '' };
        }
        lr.request.e2e = { ...(lr.request.e2e ?? {}), delivered_to_wallet: true };
        lr.events.push({ at, event: 'request.status', status: lr.request.status, seq });
        return;
      }
      case 'view':
        if (p.wallet_id !== undefined && p.wallet_id !== this.kf.wallet.wallet_id) { this.log('ignored view: it is for another wallet_id'); return; }
        if (!this.state.view || Number(p.version ?? 0) >= this.state.view.version) this.state.view = { version: Number(p.version ?? 0), payload: p, at };
        return;
      default:
        this.log(`ignored envelope ${envId}: unknown kind`);
    }
  }

  /** GET /v1/e2e/view → latest view (verified with the pinned wallet key) or the cached one. */
  async view(): Promise<any | null> {
    await this.walletId();
    const r = await this.api.req('GET', '/v1/e2e/view');
    if (r.status === 200) {
      const env = r.body?.envelope ?? r.body;
      this.update(() => { this.accept(env, undefined, true); });
    } else {
      this.reloadQuiet();
      if (r.status !== 404 && r.status >= 400) this.log(`view: HTTP ${r.status}`);
    }
    return this.state.view?.payload ?? null;
  }

  /** Waits until pred() or the timeout, reading the inbox and the shared state meanwhile. */
  async waitUntil(pred: () => boolean, seconds: number): Promise<boolean> {
    const deadline = Date.now() + seconds * 1000;
    for (;;) {
      this.reloadQuiet();
      if (pred()) return true;
      const left = (deadline - Date.now()) / 1000;
      if (left <= 0) return false;
      // short polls: another process of this agent may take the envelope; the shared state file shows it
      try { await this.sync(Math.min(5, Math.max(0, Math.floor(left)))); }
      catch (e) {
        if (!(e instanceof ApiError)) throw e;
        await new Promise((r) => setTimeout(r, Math.min(2000, Math.max(0, deadline - Date.now()))));
      }
      if (left < 1) { this.reloadQuiet(); return pred(); }
    }
  }

  // ---- requests ----

  find(requestId?: string, clientRequestId?: string): LocalRequest | undefined {
    if (requestId) return REQUEST_ID_RE.test(requestId) ? this.state.requests[requestId] : undefined;
    if (clientRequestId) { const id = this.state.by_client_id[clientRequestId]; return typeof id === 'string' ? this.state.requests[id] : undefined; }
    return undefined;
  }

  /** Local checks by the view: fields, shape, account bound, type allowed. Returns the normalized body. */
  check(args: Record<string, any>, view: any | null, forRequest: boolean) {
    const a = args && typeof args === 'object' ? args : {};
    const type = String(a.type ?? '');
    if (!(TYPES as readonly string[]).includes(type)) throw new E2EError('BAD_REQUEST', `type must be one of ${TYPES.join(', ')}`, { field: 'type' });
    const allowed = new Set([...COMMON_FIELDS, ...FIELDS_BY_TYPE[type], ...TOOL_FIELDS]);
    const body: Record<string, any> = {};
    for (const [k, v] of Object.entries(a)) {
      if (v === undefined || v === null) continue;
      if (!allowed.has(k)) throw new E2EError('BAD_REQUEST', `unknown field ${JSON.stringify(k.slice(0, 40))} for type ${type}; allowed: ${[...allowed].join(', ')}`, { field: k.slice(0, 40) });
      if (!TOOL_FIELDS.includes(k)) body[k] = v;
    }
    for (const k of STRING_FIELDS) if (body[k] !== undefined && (typeof body[k] !== 'string' || body[k].length > 128)) throw new E2EError('BAD_REQUEST', `${k} must be a string (≤ 128 characters)`, { field: k });
    for (const k of AMOUNT_FIELDS) {
      if (body[k] === undefined) continue;
      if (typeof body[k] === 'number' && Number.isFinite(body[k])) body[k] = String(body[k]);
      if (typeof body[k] !== 'string' || !/^\d{1,40}(\.\d{1,40})?$/.test(body[k])) throw new E2EError('BAD_AMOUNT', `${k} is a decimal string, e.g. "25.5"`, { field: k });
    }
    if (body.slippage_bps !== undefined && !(Number.isInteger(body.slippage_bps) && body.slippage_bps >= 1 && body.slippage_bps <= 300)) throw new E2EError('BAD_REQUEST', 'slippage_bps: integer 1…300', { field: 'slippage_bps' });
    for (const k of ['resources', 'metadata']) if (body[k] !== undefined && (typeof body[k] !== 'object' || Array.isArray(body[k]))) throw new E2EError('BAD_REQUEST', `${k} must be an object`, { field: k });
    if (body.reason !== undefined && typeof body.reason !== 'string') throw new E2EError('BAD_REQUEST', 'reason must be a string', { field: 'reason' });
    if (forRequest) {
      if (typeof body.reason !== 'string' || !body.reason.trim()) throw new E2EError('BAD_REQUEST', 'reason is required (the human sees it)', { field: 'reason' });
      if (body.reason.length > 500) throw new E2EError('BAD_REQUEST', 'reason is longer than 500 characters', { field: 'reason' });
    }
    if (body.client_request_id !== undefined && (typeof body.client_request_id !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(body.client_request_id))) throw new E2EError('BAD_REQUEST', 'client_request_id: ≤128 ASCII characters, no spaces', { field: 'client_request_id' });
    if (body.metadata !== undefined && JSON.stringify(body.metadata).length > 2048) throw new E2EError('BAD_REQUEST', 'metadata is larger than 2 KB', { field: 'metadata' });
    if (body.resources !== undefined && JSON.stringify(body.resources).length > 1024) throw new E2EError('BAD_REQUEST', 'resources is larger than 1 KB', { field: 'resources' });
    const exp = body.expires_in === undefined ? 3600 : Number(body.expires_in);
    if (!Number.isInteger(exp) || exp < 60 || exp > 86400) throw new E2EError('BAD_EXPIRES', 'expires_in: 60…86400 seconds', { field: 'expires_in' });
    if (type === 'transfer' && (!body.to || !body.amount || !body.asset)) throw new E2EError('BAD_REQUEST', 'transfer needs asset, to, amount', { field: 'to' });
    let account: any = null;
    const ag = view?.agent;
    if (ag) {
      const accs: any[] = Array.isArray(ag.accounts) ? ag.accounts.filter((x: any) => x && typeof x === 'object') : [];
      if (body.account !== undefined) {
        account = accs.find((x) => x.id === body.account || x.name === body.account);
        if (!account) throw new E2EError('ACCOUNT_NOT_BOUND', `account ${body.account} is not bound to this agent`, { field: 'account', bound: accs.map((x) => x.id) });
      } else {
        account = accs.find((x) => x.id === ag.default_account) ?? accs[0] ?? null;
      }
      if (account) body.account = account.id;
      if (Array.isArray(ag.allowed_types) && !ag.allowed_types.includes(type)) throw new E2EError('TYPE_NOT_ALLOWED', `type ${type} is not allowed for this agent (the human sets it in the wallet)`, { allowed_types: ag.allowed_types });
    }
    // 0.1.5: network served, asset listed, amount precision, recipient format — the wallet's codes, before any window
    const spend = validateIntent(type, body, account);
    return { body, type, account, expiresIn: exp, spend };
  }

  async createRequest(args: Record<string, any>): Promise<{ lr: LocalRequest; replay: boolean }> {
    await this.walletId();
    this.reload();
    if (!this.kf.paired) {
      await this.pairIfNeeded().catch((e) => this.log(`pair: ${e instanceof ApiError || e instanceof E2EError ? e.code : 'error'}`));
      await this.waitUntil(() => this.paired, 3).catch(() => false);
      if (!this.kf.paired) throw new E2EError('E2E_NOT_PAIRED', this.kf.pair?.sent_at
        ? 'pairing sent, waiting for the wallet: the human must open the extension once to finish connecting this agent'
        : 'this agent key is not paired with the wallet: reconnect the agent from the wallet (command with DAA_PAIR)');
    }
    const view = await this.view().catch(() => this.state.view?.payload ?? null);
    const { body, type, account, expiresIn } = this.check(args, view, true);
    body.client_request_id ??= 'mcp-' + uuid();
    const { metadata, ...forHash } = body;
    const bodyHash = sha256hex(canonical(forHash));
    const created = new Date();
    const request_id = 'awr_' + randomB64u(16);
    const created_at = nowSec(created), expires_at = nowSec(new Date(created.getTime() + expiresIn * 1000));
    const { expires_in, ...rest } = body;
    // protocol fields last: arguments can never set them
    const payload = { ...rest, t: 'request', request_id, created_at, expires_at };
    const env = this.sealToWallet(payload);
    const intent: Record<string, any> = {};
    for (const [k, v] of Object.entries(rest)) if (!['type', 'account', 'network', 'reason', 'metadata', 'client_request_id'].includes(k)) intent[k] = v;
    const request: Record<string, any> = {
      schema_version: '1', request_id, client_request_id: body.client_request_id,
      agent: { id: this.agentId, name: view?.agent?.name ?? this.kf.paired?.name ?? null },
      account: account ? { id: account.id, name: account.name ?? null } : (body.account ? { id: body.account } : null),
      type, network: body.network ?? (type === 'swap' ? 'tron' : null), intent, reason: body.reason, metadata: metadata ?? {},
      status: 'pending', created_at, expires_at,
      e2e: { envelope_id: env.id, delivered_to_wallet: false, signed_by: 'agent_key', agent_fp: this.kf.fp },
    };
    // reserve the client_request_id in the shared state before sending (two processes, one key)
    const prev = this.update(() => {
      const p = this.find(undefined, body.client_request_id);
      if (p) return p;
      this.state.requests[request_id] = { request, body_hash: bodyHash, env_id: env.id, sent_at: new Date().toISOString(), events: [{ at: new Date().toISOString(), event: 'request.created', status: 'pending' }] };
      this.state.by_client_id[body.client_request_id] = request_id;
      return null;
    });
    if (prev) {
      if (prev.body_hash && prev.body_hash !== bodyHash) throw new E2EError('IDEMPOTENCY_CONFLICT', `client_request_id ${body.client_request_id} was used with another body`, { request_id: prev.request.request_id });
      return { lr: prev, replay: true };
    }
    let r: { status: number; body: any };
    try { r = await this.api.req('POST', '/v1/e2e/envelopes', env); }
    catch (e) { this.unreserve(request_id, body.client_request_id); throw e; }
    if (r.status >= 400) { this.unreserve(request_id, body.client_request_id); throw Api.fromResponse(r); }
    return { lr: this.state.requests[request_id], replay: false };
  }

  private unreserve(requestId: string, crid: string) {
    try {
      this.update(() => {
        const lr = this.state.requests[requestId];
        if (lr && !lr.request.e2e?.delivered_to_wallet) { delete this.state.requests[requestId]; if (this.state.by_client_id[crid] === requestId) delete this.state.by_client_id[crid]; }
      });
    } catch { /* the request stays pending locally; it shows "unknown" after expires_at */ }
  }

  async cancel(requestId: string): Promise<LocalRequest> {
    if (!REQUEST_ID_RE.test(requestId)) throw new E2EError('BAD_REQUEST', 'request_id must look like awr_…', { field: 'request_id' });
    this.reload();
    const lr = this.find(requestId);
    if (!lr) throw new E2EError('NOT_FOUND', 'request is not known to this agent');
    const st = String(shownRequest(lr.request).status);
    if (st !== 'pending') throw new E2EError('NOT_CANCELLABLE', `request is ${st}`, { status: st });
    await this.walletId();
    const r = await this.api.req('POST', '/v1/e2e/envelopes', this.sealToWallet({ t: 'cancel', request_id: requestId }));
    if (r.status >= 400) throw Api.fromResponse(r);
    this.update(() => { const x = this.state.requests[requestId]; if (x) x.cancel_sent_at = new Date().toISOString(); });
    await this.waitUntil(() => this.state.requests[requestId]?.request.status !== 'pending', 5).catch(() => false);
    return this.state.requests[requestId] ?? lr;
  }

  /** Waits for a status condition; returns the request (as shown) and the events seen meanwhile. */
  async waitRequest(requestId: string, until: string, seconds: number) {
    this.reloadQuiet();
    const lr0 = this.state.requests[requestId];
    if (!lr0) throw new E2EError('NOT_FOUND', 'request is not known to this agent');
    const initial = String(shownRequest(lr0.request).status);
    const n0 = lr0.events.length;
    const cur = () => String(shownRequest(this.state.requests[requestId]?.request ?? lr0.request).status);
    if (seconds > 0 && !reached(until, initial, initial)) {
      await this.waitUntil(() => reached(until, initial, cur()), seconds);
    } else {
      try { await this.sync(0); } catch { /* offline: local state */ }
      this.reloadQuiet();
    }
    const lr = this.state.requests[requestId] ?? lr0;
    return { request: shownRequest(lr.request), events: lr.events.slice(n0) };
  }
}
