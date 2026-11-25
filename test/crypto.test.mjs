import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as c from '../dist/crypto.js';

const V = JSON.parse(fs.readFileSync(new URL('./fixtures/vectors.json', import.meta.url), 'utf8'));
const B = (s) => Buffer.from(s, 'base64url');

test('keys, bundles, fingerprints, key ids match the vectors', () => {
  for (const who of ['agent', 'wallet']) {
    const k = V.keys[who];
    assert.equal(c.b64u(c.ed25519Pub(B(k.sig_priv))), k.sig_pub);
    assert.equal(c.b64u(c.x25519Pub(B(k.kex_priv))), k.kex_pub);
    assert.equal(c.bundle(B(k.sig_pub), B(k.kex_pub)), k.bundle);
    assert.equal(c.fingerprint(B(k.sig_pub), B(k.kex_pub)), k.fp);
    assert.equal(c.keyId(B(k.kex_pub)), k.rk);
    const pb = c.parseBundle(k.bundle);
    assert.equal(c.b64u(pb.sig), k.sig_pub);
  }
});

test('seal reproduces the vector envelopes byte for byte (fixed eph and nonce)', () => {
  const keyOf = { agent_to_wallet_request: ['agent', 'wallet'], wallet_to_agent_status: ['wallet', 'agent'] };
  for (const v of V.envelopes.filter((e) => e.valid)) {
    const [from, to] = keyOf[v.name];
    const e = v.envelope;
    const env = c.seal({ id: e.id, wallet_id: e.wallet_id, from: e.from, to: e.to, at: e.at, payload: v.payload,
      senderSigPriv: B(V.keys[from].sig_priv), recipientKexPub: B(V.keys[to].kex_pub), eph: B(v.eph_priv), nonce: B(v.nonce) });
    assert.deepEqual(env, e, v.name);
    assert.equal(c.aad(env), v.aad);
    assert.equal(c.sigMessage(env, B(env.ct)), v.sig_message);
    assert.deepEqual(c.open(e, { senderSigPub: B(V.keys[from].sig_pub), recipientKexPriv: B(V.keys[to].kex_priv) }), v.payload);
  }
});

test('invalid vectors are rejected with the expected error', () => {
  for (const v of V.envelopes.filter((e) => !e.valid)) {
    assert.equal(c.verify(v.envelope, B(V.keys.agent.sig_pub)), false, v.name);
    assert.throws(() => c.open(v.envelope, { senderSigPub: B(V.keys.agent.sig_pub), recipientKexPriv: B(V.keys.wallet.kex_priv) }), new RegExp(v.error), v.name);
  }
});

test('wrong recipient key and tampered nonce', () => {
  const e = V.envelopes[0].envelope;
  assert.throws(() => c.open(e, { senderSigPub: B(V.keys.agent.sig_pub), recipientKexPriv: B(V.keys.agent.kex_priv) }), /E2E_WRONG_KEY/);
  const n = { ...e, n: c.b64u(Buffer.alloc(12)) };
  assert.throws(() => c.open(n, { senderSigPub: B(V.keys.agent.sig_pub), recipientKexPriv: B(V.keys.wallet.kex_priv) }), /E2E_BAD_SIGNATURE/);
  assert.throws(() => c.open({ ...e, v: 'daa-e2e-2' }, { senderSigPub: B(V.keys.agent.sig_pub), recipientKexPriv: B(V.keys.wallet.kex_priv) }), /E2E_VERSION/);
});

test('pairing proof matches the vector', () => {
  const p = V.pairing;
  assert.equal(c.pairProof(p.code, p), p.proof);
  assert.notEqual(c.pairProof(c.b64u(Buffer.alloc(16)), p), p.proof);
});

test('random seal/open round trip', () => {
  const a = c.generateKeys(), w = c.generateKeys();
  const env = c.seal({ wallet_id: 'wal_x', from: 'ag_x', to: 'wallet', payload: { t: 'request', n: 'ü' }, senderSigPriv: a.sig_priv, recipientKexPub: w.kex });
  assert.match(env.id, /^env_[A-Za-z0-9_-]{22}$/);
  assert.deepEqual(c.open(env, { senderSigPub: a.sig, recipientKexPriv: w.kex_priv }), { t: 'request', n: 'ü' });
});
