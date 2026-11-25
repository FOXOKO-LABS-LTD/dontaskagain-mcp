import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import * as c from '../dist/crypto.js';
import { Agent } from '../dist/agent.js';
import { callTool } from '../dist/mcp.js';
import { fakeMailbox, fakeExtension } from './fake.mjs';

const AG = 'ag_testagent1', TOKEN = `aw_${AG}_SECRETSECRET`;
const CLI = new URL('../dist/cli.js', import.meta.url).pathname;

async function setup({ onRequest } = {}) {
  const walletPriv = { sig: c.generateKeys().sig_priv, kex: c.generateKeys().kex_priv };
  const W = { sig: c.ed25519Pub(walletPriv.sig), kex: c.x25519Pub(walletPriv.kex) };
  const box = fakeMailbox({ walletKeys: W, agents: { [TOKEN]: AG } });
  const url = await box.listen();
  const code = c.randomB64u(16);
  const ext = fakeExtension({ box, walletPriv, codes: { [AG]: code }, onRequest });
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'daa-test-'));
  const logs = [];
  const cfg = { url, token: TOKEN, walletBundle: c.bundle(W.sig, W.kex), pairCode: code, home, log: (s) => logs.push(s) };
  return { box, url, code, ext, home, cfg, logs, W, close: async () => { await box.close(); fs.rmSync(home, { recursive: true, force: true }); } };
}

test('pairing: key file 0600 in a 0700 folder, pair → paired, whoami', async () => {
  const s = await setup();
  try {
    const a = new Agent(s.cfg).init();
    const kf = path.join(s.home, 'agents', `${AG}.json`);
    assert.equal(fs.statSync(kf).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(kf)).mode & 0o777, 0o700);
    assert.equal(await a.pairIfNeeded(), 'sent');
    assert.equal(await a.waitUntil(() => a.paired, 5), true);
    assert.equal(s.ext.rejected.length, 0);
    const who = a.whoami();
    assert.equal(who.agent_fp, c.fingerprint(s.ext.bound[AG].sig, s.ext.bound[AG].kex));
    assert.equal(who.wallet_fp, s.ext.wfp);
    // the pair is sent once per code
    assert.equal(await a.pairIfNeeded(), 'paired');
    assert.equal(s.box.toWallet.length, 1);
    // nothing in the server's hands is the private key or the code
    const all = JSON.stringify(s.box.toWallet);
    assert.ok(!all.includes(s.code) && !all.includes(JSON.parse(fs.readFileSync(kf, 'utf8')).keys.sig_priv));
  } finally { await s.close(); }
});

test('request → wallet decrypts → human rejects → agent gets the status; server sees no content', async () => {
  const s = await setup({ onRequest: (req, answer) => setTimeout(() => answer({ status: 'rejected', decision: { by: 'human', via: 'extension' } }), 100) });
  try {
    const a = new Agent(s.cfg).init();
    await a.pairIfNeeded(); await a.waitUntil(() => a.paired, 5);
    const [res, isErr] = await callTool(a, 'wallet_request', { type: 'transfer', network: 'tron', asset: 'USDT', to: 'TDp9tmfuQhS2SB7Kzhp3FzexghLAZnUqFb', amount: '25.00', reason: 'Оплата счёта #118', wait_seconds: 10 });
    assert.equal(isErr, false, JSON.stringify(res));
    assert.equal(res.status, 'rejected');
    assert.equal(res.decision.by, 'human');
    assert.match(res.summary, /rejected/);
    const got = s.ext.seen.find((x) => x.payload.t === 'request');
    assert.equal(got.payload.amount, '25.00');
    assert.equal(got.payload.account, 'acc_main0001'); // default account from the view
    const wire = JSON.stringify(s.box.toWallet) + JSON.stringify(s.box.toAgent) + s.box.log.join('\n');
    for (const secret of ['25.00', 'TDp9tmfuQhS2SB7Kzhp3FzexghLAZnUqFb', 'Оплата', '#118', 'USDT', 'transfer']) assert.ok(!wire.includes(secret), `server sees ${secret}`);
    // status by client_request_id from local state
    const [st] = await callTool(a, 'wallet_request_status', { client_request_id: res.client_request_id });
    assert.equal(st.status, 'rejected');
    const [h] = await callTool(a, 'wallet_history', {});
    assert.equal(h.items.length, 1);
    const [ws] = await callTool(a, 'wallet_status', {});
    assert.equal(ws.e2e.paired, true);
    assert.equal(ws.accounts[0].name, 'main');
    assert.equal(ws.address_book.length, 1);
  } finally { await s.close(); }
});

test('a status not signed by the pinned wallet key is ignored', async () => {
  let reqSeen;
  const s = await setup({ onRequest: (req) => { reqSeen = req; } });
  try {
    const a = new Agent(s.cfg).init();
    await a.pairIfNeeded(); await a.waitUntil(() => a.paired, 5);
    const [res] = await callTool(a, 'wallet_request', { type: 'transfer', network: 'tron', asset: 'USDT', to: 'TDp9tmfuQhS2SB7Kzhp3FzexghLAZnUqFb', amount: '1', reason: 'x', wait_seconds: 1 });
    assert.equal(res.status, 'pending');
    // the server forges "confirmed" with its own key
    const forger = c.generateKeys();
    const forged = c.seal({ wallet_id: 'wal_test0001', from: 'wallet', to: AG, payload: { t: 'status', event: 'request.status', request: { ...reqSeen, status: 'confirmed', tx: { tx_id: 'fake' } } }, senderSigPriv: forger.sig_priv, recipientKexPub: s.ext.bound[AG].kex });
    s.box.pushToAgent(AG, forged);
    const [st] = await callTool(a, 'wallet_request_status', { request_id: res.request_id, wait_seconds: 1, until: 'change' });
    assert.equal(st.status, 'pending');
    assert.ok(s.logs.some((l) => l.includes('ignored envelope') && l.includes(forged.id)));
    // and a request forged by the server (other key, from = this agent) is rejected by the wallet
    const fr = c.seal({ wallet_id: 'wal_test0001', from: AG, to: 'wallet', payload: { t: 'request', request_id: 'awr_forged', type: 'transfer' }, senderSigPriv: forger.sig_priv, recipientKexPub: s.W.kex });
    s.box.toWallet.push({ seq: 999, envelope: fr }); s.box.ev.emit('wallet', { seq: 999, envelope: fr });
    assert.ok(s.ext.rejected.some((r) => r.id === fr.id && /E2E_BAD_SIGNATURE/.test(r.error)));
  } finally { await s.close(); }
});

test('local expiry, idempotent replay and conflict, cancel', async () => {
  const s = await setup();
  try {
    const a = new Agent(s.cfg).init();
    await a.pairIfNeeded(); await a.waitUntil(() => a.paired, 5);
    const args = { type: 'transfer', network: 'tron', asset: 'TRX', to: 'TDp9tmfuQhS2SB7Kzhp3FzexghLAZnUqFb', amount: '5', reason: 'r', client_request_id: 'inv-1', wait_seconds: 0 };
    const [r1] = await callTool(a, 'wallet_request', args);
    const [r2] = await callTool(a, 'wallet_request', args);
    assert.equal(r2.request_id, r1.request_id);
    assert.equal(r2.idempotent_replay, true);
    const [r3, e3] = await callTool(a, 'wallet_request', { ...args, amount: '6' });
    assert.equal(e3, true); assert.equal(r3.error.code, 'IDEMPOTENCY_CONFLICT');
    assert.equal(s.box.toWallet.filter((x) => x.envelope.from === AG).length, 2); // pair + one request
    // cancel
    const [cx] = await callTool(a, 'wallet_cancel', { request_id: r1.request_id });
    assert.equal(cx.status, 'cancelled');
    // expiry
    const [r4] = await callTool(a, 'wallet_request', { ...args, client_request_id: 'inv-2' });
    // past expires_at without a wallet status: "unknown" (not a made-up "expired"), the stored status stays pending
    a.update(() => { a.state.requests[r4.request_id].request.expires_at = new Date(Date.now() - 1000).toISOString(); });
    const [st] = await callTool(a, 'wallet_request_status', { request_id: r4.request_id });
    assert.equal(st.status, 'unknown');
    assert.equal(st.e2e.no_status_from_wallet, true);
    assert.equal(st.error, undefined);
    assert.match(st.summary, /do not repeat/);
    assert.equal(a.state.requests[r4.request_id].request.status, 'pending');
  } finally { await s.close(); }
});

test('view checks: account not bound, type not allowed; preview is local', async () => {
  const s = await setup();
  try {
    const a = new Agent(s.cfg).init();
    await a.pairIfNeeded(); await a.waitUntil(() => a.paired, 5);
    const n0 = s.box.toWallet.length;
    const [e1, x1] = await callTool(a, 'wallet_request', { type: 'transfer', account: 'acc_other', network: 'tron', asset: 'TRX', to: 'T1', amount: '1', reason: 'r' });
    assert.equal(x1, true); assert.equal(e1.error.code, 'ACCOUNT_NOT_BOUND');
    const [e2] = await callTool(a, 'wallet_request', { type: 'bridge', from_network: 'evm:1', to_network: 'evm:8453', asset: 'USDC', amount: '1', reason: 'r' });
    assert.equal(e2.error.code, 'TYPE_NOT_ALLOWED');
    const [pv] = await callTool(a, 'wallet_preview', { type: 'transfer', network: 'tron', asset: 'USDT', to: 'TDp9tmfuQhS2SB7Kzhp3FzexghLAZnUqFb', amount: '1' });
    assert.equal(pv.decision, 'human'); assert.deepEqual(pv.checks.to_in_address_book, { label: 'Склад' });
    assert.equal(s.box.toWallet.length, n0); // nothing sent
  } finally { await s.close(); }
});

test('wallet key pinning and key rotation on a new pairing code', async () => {
  const s = await setup();
  try {
    const a = new Agent(s.cfg).init();
    await a.pairIfNeeded(); await a.waitUntil(() => a.paired, 5);
    const fp1 = a.kf.fp;
    const other = c.generateKeys();
    assert.throws(() => new Agent({ ...s.cfg, walletBundle: c.bundle(other.sig, other.kex) }).init(), (e) => e.code === 'E2E_WALLET_KEY_CHANGED');
    // the same code again: same key
    assert.equal(new Agent(s.cfg).init().kf.fp, fp1);
    // a new code for a paired key: rotation, the old file kept as .old
    const b = new Agent({ ...s.cfg, pairCode: c.randomB64u(16) }).init();
    assert.notEqual(b.kf.fp, fp1);
    assert.equal(b.paired, false);
    assert.ok(fs.existsSync(path.join(s.home, 'agents', `${AG}.json.old`)));
    // too wide permissions: refused (fail closed), not a warning
    fs.chmodSync(path.join(s.home, 'agents', `${AG}.json`), 0o644);
    assert.throws(() => new Agent({ ...s.cfg, pairCode: undefined }).init(), (e) => e.code === 'E2E_KEY_FILE_PERMS' && /expected 600/.test(e.message));
  } finally { await s.close(); }
});

test('stdio MCP: initialize, tools/list, tools/call over the CLI', async () => {
  const s = await setup({ onRequest: (req, answer) => setTimeout(() => answer({ status: 'rejected', decision: { by: 'human' } }), 50) });
  try {
    const p = spawn(process.execPath, [CLI], { env: { ...process.env, DAA_URL: s.url, DAA_TOKEN: TOKEN, DAA_WALLET: s.cfg.walletBundle, DAA_PAIR: s.code, DAA_HOME: s.home }, stdio: ['pipe', 'pipe', 'pipe'] });
    const answers = new Map();
    let buf = '';
    p.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); answers.set(m.id, m); } });
    const call = (id, method, params) => { p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'); return new Promise((r) => { const t = setInterval(() => { if (answers.has(id)) { clearInterval(t); r(answers.get(id)); } }, 20); }); };
    const init = await call(1, 'initialize', { protocolVersion: '2025-06-18' });
    assert.equal(init.result.serverInfo.name, 'dontaskagain');
    const list = await call(2, 'tools/list', {});
    assert.deepEqual(list.result.tools.map((t) => t.name), ['wallet_status', 'wallet_preview', 'wallet_request', 'wallet_request_status', 'wallet_cancel', 'wallet_history']);
    // wait for the pairing done by the server process at start
    for (let i = 0; i < 50 && !s.ext.bound[AG]; i++) await new Promise((r) => setTimeout(r, 50));
    const r = await call(3, 'tools/call', { name: 'wallet_request', arguments: { type: 'transfer', network: 'tron', asset: 'USDT', to: 'TDp9tmfuQhS2SB7Kzhp3FzexghLAZnUqFb', amount: '2', reason: 'cli', wait_seconds: 10 } });
    assert.equal(r.result.isError, false, r.result.content[0].text);
    assert.equal(r.result.structuredContent.status, 'rejected');
    p.stdin.end();
    await new Promise((r2) => p.on('exit', r2));
  } finally { await s.close(); }
});
