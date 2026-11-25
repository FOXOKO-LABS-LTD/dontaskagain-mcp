#!/usr/bin/env node
// dontaskagain-mcp — agent side of the Don't Ask Again wallet.
//   dontaskagain-mcp            stdio MCP server (Claude Code: claude mcp add … -- npx -y dontaskagain-mcp@<exact version>)
//   dontaskagain-mcp whoami     agent id, key fingerprint (compare with the wallet), wallet fingerprint, paired — read-only:
//                               no network, never touches the inbox of a running server, never rotates the key
//   dontaskagain-mcp pair       send the pairing (DAA_PAIR) and wait for the wallet to confirm (up to 10 min)
//   dontaskagain-mcp --version
import { Agent, configFromEnv, E2EError, VERSION } from './agent.js';
import { handle, serveStdio } from './mcp.js';
import { ApiError } from './api.js';
import { withHint } from './hints.js';

const HELP = `dontaskagain-mcp ${VERSION} — agent side of the Don't Ask Again wallet (end-to-end encrypted)

Usage:
  dontaskagain-mcp            stdio MCP server
  dontaskagain-mcp whoami     show the agent key fingerprint to compare with the wallet
  dontaskagain-mcp pair       pair now and wait until the wallet confirms
  dontaskagain-mcp --version

Environment (the wallet's "connect agent" wizard gives the exact command):
  DAA_CONFIG   file with the variables below as KEY=VALUE lines (mode 600) —
               keeps the token and the code out of the command line
  DAA_URL      Signer address (https)    DAA_TOKEN      agent token aw_…
  DAA_WALLET   wallet key (sig.kex)      DAA_WALLET_ID  wallet id wal_…
  DAA_PAIR     one-time pairing code     DAA_HOME       key folder (default ~/.dontaskagain)
`;

async function main() {
  const arg = process.argv[2] ?? '';
  if (arg === '--version' || arg === '-v' || arg === 'version') { process.stdout.write(VERSION + '\n'); return; }
  if (arg === '--help' || arg === '-h' || arg === 'help') { process.stdout.write(HELP); return; }
  if (arg === 'whoami') {
    // read-only: creates the first key if there is none, otherwise changes nothing and does not read the inbox
    const a = new Agent(configFromEnv()).init({ readOnly: true });
    process.stdout.write(JSON.stringify(a.whoami(), null, 2) + '\n');
    return;
  }
  if (arg && arg !== 'pair') { process.stderr.write(HELP); process.exitCode = 2; return; }
  let cfg: ReturnType<typeof configFromEnv> | null = null, initError = '';
  try { cfg = configFromEnv(); } catch (e: any) { initError = `${e?.code ?? 'E2E_NOT_CONFIGURED'}: ${e instanceof E2EError ? e.message : 'configuration error'}`; }
  if (arg === 'pair') {
    if (!cfg) throw new E2EError('E2E_NOT_CONFIGURED', initError);
    const a = new Agent(cfg).init();
    const r = await a.pairIfNeeded();
    if (r === 'none') { process.stderr.write(a.paired ? 'already paired\n' : 'nothing to pair: set DAA_PAIR from the wallet\n'); process.exitCode = a.paired ? 0 : 2; return; }
    process.stderr.write(`pairing sent; agent key fingerprint ${a.kf.fp} — open the wallet; waiting for its confirmation…\n`);
    const ok = await a.waitUntil(() => a.paired, 600);
    process.stdout.write(JSON.stringify(a.whoami(), null, 2) + '\n');
    process.exitCode = ok ? 0 : 3;
    return;
  }
  // MCP: a configuration error is answered by every tool instead of a dead server (our own text only, never a file's contents)
  let agent: Agent | null = null;
  if (cfg) try { agent = new Agent(cfg).init(); } catch (e: any) { initError = `${e?.code ?? 'E2E_NOT_CONFIGURED'}: ${e instanceof E2EError ? e.message : 'cannot start (' + (e?.code ?? 'error') + ')'}`; }
  if (initError) process.stderr.write(`dontaskagain-mcp: ${initError}\n`);
  if (agent) {
    agent.pairIfNeeded().then((r) => { if (r === 'sent') process.stderr.write(`dontaskagain-mcp: pairing sent, agent key fingerprint ${agent!.kf.fp}\n`); })
      .catch((e) => process.stderr.write(`dontaskagain-mcp: pairing: ${e?.code ?? 'error'}: ${e instanceof E2EError || e instanceof ApiError ? e.message : 'not sent yet'}\n`));
    await serveStdio(agent);
  } else {
    const readline = await import('node:readline');
    const rl = readline.createInterface({ input: process.stdin });
    for await (const line of rl) {
      let req: any; try { req = JSON.parse(line); } catch { continue; }
      if (req.id === undefined || req.id === null) continue;
      let out: any;
      if (req.method === 'tools/call') {
        const res = withHint({ error: { code: 'E2E_NOT_CONFIGURED', message: initError }, summary: initError }, 'E2E_NOT_CONFIGURED');
        out = { jsonrpc: '2.0', id: req.id, result: { content: [{ type: 'text', text: JSON.stringify(res) }], structuredContent: res, isError: true } };
      } else out = await handle(null as any, req);
      process.stdout.write(JSON.stringify(out) + '\n');
    }
  }
}

main().catch((e) => { process.stderr.write(`dontaskagain-mcp: ${e?.code ? e.code + ': ' : ''}${e instanceof E2EError || e instanceof ApiError ? e.message : 'error'}\n`); process.exitCode = 1; });
