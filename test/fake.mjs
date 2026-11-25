// Fake Signer mailbox (agent side) and a fake extension built on the same primitives — for tests only.
import http from 'node:http';
import { EventEmitter } from 'node:events';
import * as c from '../dist/crypto.js';

export function fakeMailbox({ walletId = 'wal_test0001', walletKeys, agents }) {
  // agents: { token: agentId }
  const ev = new EventEmitter();
  ev.setMaxListeners(100);
  let seq = 0;
  const toWallet = [];          // {seq, envelope}
  const toAgent = {};           // agentId -> [{seq, envelope}]
  const views = {};             // agentId -> envelope
  const ids = new Map();        // env id -> json
  const log = [];
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const send = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    const tok = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    const agent = agents[tok];
    if (!agent) return send(401, { error: { code: 'UNAUTHORIZED', message: 'unknown token' } });
    let body = '';
    for await (const ch of req) body += ch;
    log.push(`${req.method} ${u.pathname} ${body.length}`);
    if (req.method === 'GET' && u.pathname === '/v1/e2e/info') {
      return send(200, { schema_version: '1', e2e_mode: 'required', wallet_id: walletId, wallet_key: c.bundle(walletKeys.sig, walletKeys.kex), wallet_fp: c.fingerprint(walletKeys.sig, walletKeys.kex), agent: { id: agent, key_mode: 'agent' }, extension: { online: true, unlocked: true } });
    }
    if (req.method === 'POST' && u.pathname === '/v1/e2e/envelopes') {
      const env = JSON.parse(body);
      try { c.checkShape(env); } catch (e) { return send(400, { error: { code: 'E2E_BAD_ENVELOPE', message: e.message } }); }
      if (env.from !== agent || env.wallet_id !== walletId || env.to !== 'wallet') return send(403, { error: { code: 'E2E_FROM_MISMATCH', message: 'header' } });
      if (ids.has(env.id)) return ids.get(env.id) === body ? send(200, { id: env.id }) : send(409, { error: { code: 'E2E_DUPLICATE', message: 'dup' } });
      ids.set(env.id, body);
      const it = { seq: ++seq, envelope: env };
      toWallet.push(it);
      ev.emit('wallet', it);
      return send(201, { id: env.id, seq: it.seq });
    }
    if (req.method === 'GET' && u.pathname === '/v1/e2e/envelopes') {
      const after = Number(u.searchParams.get('after') ?? 0), wait = Number(u.searchParams.get('wait') ?? 0);
      const pick = () => (toAgent[agent] ?? []).filter((x) => x.seq > after);
      let list = pick();
      if (!list.length && wait > 0) {
        await new Promise((r) => { const t = setTimeout(done, wait * 1000); function done() { clearTimeout(t); ev.off('agent:' + agent, done); r(); } ev.on('agent:' + agent, done); });
        list = pick();
      }
      return send(200, { envelopes: list, next_after: list.length ? list[list.length - 1].seq : after });
    }
    if (req.method === 'POST' && u.pathname === '/v1/e2e/envelopes/ack') {
      const { up_to_seq } = JSON.parse(body || '{}');
      toAgent[agent] = (toAgent[agent] ?? []).filter((x) => x.seq > up_to_seq);
      return send(200, { ok: true });
    }
    if (req.method === 'GET' && u.pathname === '/v1/e2e/view') {
      return views[agent] ? send(200, { envelope: views[agent] }) : send(404, { error: { code: 'E2E_VIEW_NOT_SYNCED', message: 'no view' } });
    }
    if (req.method === 'GET' && u.pathname === '/v1/wallet') {
      return send(200, api.walletBody ?? { schema_version: '1', e2e: true, accounts: [{ id: 'acc_main0001', addresses: { tron: 'TSZuTestAddr' }, balances: {} }], extension: { online: true, unlocked: true } });
    }
    send(404, { error: { code: 'NOT_FOUND', message: u.pathname } });
  });
  const api = {
    ev, toWallet, toAgent, views, log, walletBody: null,
    pushToAgent(agentId, env) { const it = { seq: ++seq, envelope: env }; (toAgent[agentId] ??= []).push(it); ev.emit('agent:' + agentId, it); return it; },
    listen: () => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${srv.address().port}`))),
    close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }),
  };
  return api;
}

/** Fake extension: pairing with a code, view, and a programmable answer to each request. */
export function fakeExtension({ box, walletId = 'wal_test0001', walletPriv, codes, onRequest }) {
  const W = { sig_priv: walletPriv.sig, kex_priv: walletPriv.kex, sig: c.ed25519Pub(walletPriv.sig), kex: c.x25519Pub(walletPriv.kex) };
  const wfp = c.fingerprint(W.sig, W.kex);
  const bound = {};        // agentId -> {sig, kex}
  const seen = [];
  const rejected = [];
  const sealTo = (agentId, payload) => c.seal({ wallet_id: walletId, from: 'wallet', to: agentId, payload, senderSigPriv: W.sig_priv, recipientKexPub: bound[agentId].kex });
  const view = (agentId, extra = {}) => ({ t: 'view', version: 1, wallet_id: walletId, agent: { id: agentId, name: 'claude-bot', accounts: [{ id: 'acc_main0001', name: 'main', addresses: { tron: 'TSZuTestAddr' } }], default_account: 'acc_main0001', allowed_types: ['transfer', 'swap'], rules: {} }, address_book: [{ id: 'ab_1', label: 'Склад', network: 'tron', address: 'TDp9tmfuQhS2SB7Kzhp3FzexghLAZnUqFb' }], networks_trusted: ['tron'], global: {}, ...extra });
  box.ev.on('wallet', ({ envelope: env }) => {
    try {
      if (!bound[env.from]) {
        const p = c.decryptOnly(env, W.kex_priv);
        if (p.t !== 'pair') throw new Error('unknown agent');
        const keys = { sig: Buffer.from(p.keys.sig, 'base64url'), kex: Buffer.from(p.keys.kex, 'base64url') };
        if (!c.verify(env, keys.sig)) throw new Error('E2E_BAD_SIGNATURE');
        const code = codes[env.from];
        if (!code || c.pairProof(code, { wallet_id: walletId, agent_id: env.from, sig: p.keys.sig, kex: p.keys.kex, wallet_fp: wfp }) !== p.proof) throw new Error('bad proof');
        bound[env.from] = keys;
        box.views[env.from] = sealTo(env.from, view(env.from));
        box.pushToAgent(env.from, sealTo(env.from, { t: 'paired', agent_id: env.from, agent_fp: c.fingerprint(keys.sig, keys.kex), wallet_fp: wfp, name: 'claude-bot' }));
        return;
      }
      const p = c.open(env, { senderSigPub: bound[env.from].sig, recipientKexPriv: W.kex_priv });
      seen.push({ from: env.from, payload: p });
      if (p.t === 'request') {
        const req = { schema_version: '1', request_id: p.request_id, client_request_id: p.client_request_id, agent: { id: env.from, name: 'claude-bot' }, type: p.type, network: p.network, intent: { asset: p.asset, to: p.to, amount: p.amount }, reason: p.reason, created_at: p.created_at, expires_at: p.expires_at, status: 'pending' };
        box.pushToAgent(env.from, sealTo(env.from, { t: 'status', event: 'request.created', request: req }));
        onRequest?.(req, (patch, event = 'request.status') => box.pushToAgent(env.from, sealTo(env.from, { t: 'status', event, request: { ...req, ...patch } })));
      }
      if (p.t === 'cancel') {
        box.pushToAgent(env.from, sealTo(env.from, { t: 'status', event: 'request.status', request: { request_id: p.request_id, status: 'cancelled' } }));
      }
    } catch (e) { rejected.push({ id: env.id, error: e.message }); }
  });
  return { W, wfp, bound, seen, rejected, sealTo, view, codes };
}
