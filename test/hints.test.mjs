// 0.1.3: error codes come with a hint for the model and a sentence for the human (our own text, not the protocol's).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import * as c from '../dist/crypto.js';
import { Agent, VERSION } from '../dist/agent.js';
import { callTool, requestAnswer } from '../dist/mcp.js';
import { hintFor, withHint, HINT_CODES } from '../dist/hints.js';
import { fakeMailbox, fakeExtension } from './fake.mjs';

const AG = 'ag_testagent1', TOKEN = `aw_${AG}_SECRETSECRET`;
const CLI = new URL('../dist/cli.js', import.meta.url).pathname;

test('hints: every code the brief names has do + tell_human', () => {
  for (const code of ['AGENTS_PAUSED', 'BUILD_FAILED', 'INSUFFICIENT_GAS', 'INVITE_REQUIRED', 'RATE_LIMITED', 'DECISION_NOT_ALLOWED']) {
    const h = hintFor(code);
    assert.ok(h, code);
    assert.ok(h.do.length > 20 && h.tell_human.length > 20, code);
    assert.ok(HINT_CODES.includes(code));
  }
  assert.equal(hintFor('SOMETHING_ELSE'), undefined);
  assert.equal(hintFor(undefined), undefined);
});

test('hints: BUILD_FAILED "signal timed out" → network access / read everything through the Signer', () => {
  const h = hintFor('BUILD_FAILED', 'signal timed out');
  assert.match(h.tell_human, /Read everything through the Signer/);
  assert.notEqual(h, hintFor('BUILD_FAILED', 'SELF_TRANSFER'));
  assert.match(hintFor('BUILD_FAILED', 'TimeoutError').tell_human, /network/);
});

test('hints: withHint adds hint and extends summary; unknown code leaves the answer as is', () => {
  const o = withHint({ summary: 'error RATE_LIMITED: x' }, 'RATE_LIMITED');
  assert.deepEqual(Object.keys(o.hint), ['do', 'tell_human']);
  assert.match(o.summary, /^error RATE_LIMITED: x — .*Tell the human: "/);
  const same = { summary: 's' };
  assert.equal(withHint(same, 'NOPE'), same);
});

test('requestAnswer: final with error.code → hint; pending → none', () => {
  const r = requestAnswer({ request_id: 'awr_1', status: 'rejected', error: { code: 'AGENTS_PAUSED', message: '' } });
  assert.match(r.summary, /rejected/);
  assert.match(r.hint.tell_human, /paused/);
  const p = requestAnswer({ request_id: 'awr_2', status: 'pending' });
  assert.equal(p.hint, undefined);
  const b = requestAnswer({ request_id: 'awr_3', status: 'failed', error: { code: 'BUILD_FAILED', message: 'signal timed out' } });
  assert.match(b.hint.tell_human, /Read everything through the Signer/);
});

test('flow: the wallet rejects with AGENTS_PAUSED → the tool answer carries the hint', async () => {
  const walletPriv = { sig: c.generateKeys().sig_priv, kex: c.generateKeys().kex_priv };
  const W = { sig: c.ed25519Pub(walletPriv.sig), kex: c.x25519Pub(walletPriv.kex) };
  const box = fakeMailbox({ walletKeys: W, agents: { [TOKEN]: AG } });
  const url = await box.listen();
  const code = c.randomB64u(16);
  fakeExtension({ box, walletPriv, codes: { [AG]: code },
    onRequest: (req, answer) => setTimeout(() => answer({ status: 'rejected', decision: { by: 'extension' }, error: { code: 'AGENTS_PAUSED', message: 'all agents are paused by the human' } }), 50) });
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'daa-hint-'));
  try {
    const a = new Agent({ url, token: TOKEN, walletBundle: c.bundle(W.sig, W.kex), pairCode: code, home, log: () => {} }).init();
    await a.pairIfNeeded(); await a.waitUntil(() => a.paired, 5);
    const [res, isErr] = await callTool(a, 'wallet_request', { type: 'transfer', network: 'tron', asset: 'USDT', to: 'TKHbK1wFcPpHHp3oDCm9HnrSsB9Mt5SU4A', amount: '1', reason: 'test', wait_seconds: 10 });
    assert.equal(isErr, false);
    assert.equal(res.status, 'rejected');
    assert.equal(res.error.code, 'AGENTS_PAUSED');
    assert.match(res.hint.do, /paused/);
    assert.match(res.summary, /Tell the human/);
    // an HTTP error of the Signer gets the hint too (unknown request → NOT_FOUND has none; RATE_LIMITED from the box has one)
    const [nf] = await callTool(a, 'wallet_request_status', { request_id: 'awr_nope' });
    assert.equal(nf.hint, undefined);
  } finally { await box.close(); fs.rmSync(home, { recursive: true, force: true }); }
});

test('cli: not configured → every tool answers E2E_NOT_CONFIGURED with a hint; --version', async () => {
  const run = (args, input, env) => new Promise((res) => {
    const p = spawn(process.execPath, [CLI, ...args], { env: { PATH: process.env.PATH, HOME: os.tmpdir(), ...env } });
    let out = ''; p.stdout.on('data', (d) => { out += d; }); p.on('close', () => res(out));
    if (input) p.stdin.end(input); else p.stdin.end();
  });
  assert.equal((await run(['--version'])).trim(), VERSION);
  assert.equal(VERSION, '0.1.4');
  const out = await run([], JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'wallet_status', arguments: {} } }) + '\n', {});
  const r = JSON.parse(out.trim().split('\n')[0]).result.structuredContent;
  assert.equal(r.error.code, 'E2E_NOT_CONFIGURED');
  assert.match(r.hint.tell_human, /Connect agent/);
});
