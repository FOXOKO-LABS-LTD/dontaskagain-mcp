# dontaskagain-mcp

**The agent asks — the human signs every transaction. Keys never leave the browser.**

The agent side of the [Don't Ask Again](https://dontaskagain.xyz) wallet: a stdio MCP server through which an AI agent
(Claude Code, OpenAI Codex or any MCP client) asks the human's wallet for simple operations — transfer, swap, USDC
bridge, gas refuel. The human reviews and signs every transaction in the
[Chrome extension](https://github.com/FOXOKO-LABS-LTD/dontaskagain-agent-wallet); the wallet never signs on its own.

**End-to-end encryption.** The agent key is created and kept on the agent's machine. Every request is signed with it
and encrypted to the wallet's key. The Signer server (including the public one operated by FOXOKO LABS LTD) is only a
mailbox: it sees who writes to whom, when and how many bytes, but not amounts, recipients, reasons, the human's
decisions or rules. It cannot forge a request on the agent's behalf — the extension accepts only requests with a
valid signature of the agent key.

Website: https://dontaskagain.xyz · For agents: [llms.txt](https://dontaskagain.xyz/llms.txt),
[SKILL.md](https://dontaskagain.xyz/SKILL.md), [llms-full.txt](https://dontaskagain.xyz/llms-full.txt)

Node.js ≥ 20.19. No runtime dependencies (only `node:crypto`, `fetch`, `fs`). Linux and macOS; on Windows file
modes (0600/0700) are not checked — the key is protected only by the user profile permissions.

## Install

From npm ([dontaskagain-mcp](https://www.npmjs.com/package/dontaskagain-mcp)):

```bash
npx -y dontaskagain-mcp@0.1.5
```

Always pin the exact version — without it (or with `@latest`) npx would silently run whatever
was published last; the extension wizard pins the version it was tested with.

Fallback without access to the npm registry: the same version from the website archive (sha256 next to it:
`https://dontaskagain.xyz/dl/dontaskagain-mcp-0.1.5.tgz.sha256`, all files: https://dontaskagain.xyz/dl/latest.json):

```bash
npx -y -p https://dontaskagain.xyz/dl/dontaskagain-mcp-0.1.5.tgz dontaskagain-mcp
```

## Connect an agent

The wallet builds the whole command for you: **Agents → Connect agent** in the extension, choose the MCP client and
"npx on the agent's machine". Secrets (token, pairing code) go into a **file**, not the command line (otherwise they
are visible in the process list and stay in the shell history). The wallet gives you `dontaskagain-<name>.env`:

```
DAA_URL=https://<Signer address>
DAA_TOKEN=aw_…
DAA_WALLET=<wallet key sig.kex>
DAA_WALLET_ID=wal_…
DAA_PAIR=<pairing code>
```

**Claude Code**

```bash
mkdir -p -m 700 ~/.dontaskagain
mv ~/Downloads/dontaskagain-<name>.env ~/.dontaskagain/ && chmod 600 ~/.dontaskagain/dontaskagain-<name>.env
claude mcp add -s user dontaskagain-<name> -e DAA_CONFIG=~/.dontaskagain/dontaskagain-<name>.env -- npx -y dontaskagain-mcp@0.1.5
```

**OpenAI Codex** (`~/.codex/config.toml`, shared by the CLI and the IDE extension) — the same two file lines, then:

```toml
[mcp_servers.dontaskagain-<name>]
command = "npx"
args = ["-y", "dontaskagain-mcp@0.1.5"]
env = { DAA_CONFIG = "~/.dontaskagain/dontaskagain-<name>.env" }
startup_timeout_sec = 60
tool_timeout_sec = 330
```

or `codex mcp add dontaskagain-<name> --env DAA_CONFIG=~/.dontaskagain/dontaskagain-<name>.env -- npx -y dontaskagain-mcp@0.1.5`
and add the two timeout lines yourself (the default 60 s tool timeout cuts `wallet_request_status`, which waits up
to 300 s). Check with `codex mcp list`.

**Any MCP client (stdio, JSON)**

```json
{
  "mcpServers": {
    "dontaskagain-<name>": {
      "command": "npx",
      "args": ["-y", "dontaskagain-mcp@0.1.5"],
      "env": { "DAA_CONFIG": "~/.dontaskagain/dontaskagain-<name>.env" }
    }
  }
}
```

The file must belong to you and have mode 0600, otherwise the package refuses to start (`E2E_CONFIG_PERMS`).
Environment variables, when set, take precedence over the file.

On the first start the package:
1. creates the agent key pair (Ed25519 for signatures, X25519 for encryption) in `~/.dontaskagain/agents/<agent_id>.json`
   (mode 0600, folder 0700);
2. sends a `pair` envelope to the wallet: the agent public keys plus a proof of knowing the pairing code (HMAC);
3. waits until the human opens the wallet: the extension checks the code and the signature, binds the key and answers
   `paired`.

The wizard shows the **agent key fingerprint** (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`). Compare it with:

```bash
DAA_CONFIG=~/.dontaskagain/dontaskagain-<name>.env npx -y dontaskagain-mcp@0.1.5 whoami
```

(or `wallet_status` → `e2e.agent_fp`). If it does not match, press "Does not match" in the wallet and reconnect the
agent. `whoami` is read-only: no network, does not touch the inbox, never changes the key. After pairing the code is
spent and the `DAA_PAIR` line can be removed.

### Remote MCP (simpler, but the agent key is on the server)

```bash
claude mcp add -s user --transport http dontaskagain-<name> <Signer address>/mcp --header "Authorization: Bearer <aw_…>"
```

This package is not needed then, but the server holds the agent key, so its operator sees this agent's requests.
The wallet marks such requests accordingly.

## Environment

| Variable | What | Required |
|---|---|---|
| `DAA_CONFIG` | file with the variables below (`KEY=VALUE`, `#` comments, mode 0600) | no (recommended) |
| `DAA_URL` | Signer address: `https://` only; `http://` only for `localhost`, `127.0.0.0/8`, `::1` and private networks; no user/password | yes |
| `DAA_TOKEN` | agent token `aw_ag_…_…` (the `agent_id` is taken from it) | yes |
| `DAA_WALLET` | wallet public key `<ed25519>.<x25519>` (base64url), pinned at the first start | on first start |
| `DAA_WALLET_ID` | wallet id `wal_…`, pinned at once; without it the id comes from the server and is provisional until `paired` | no (recommended) |
| `DAA_PAIR` | one-time pairing code (24 h) | for pairing |
| `DAA_HOME` | key and state folder, default `~/.dontaskagain` | no |

## Commands

| Command | What |
|---|---|
| `dontaskagain-mcp` | stdio MCP server (how MCP clients start it) |
| `dontaskagain-mcp whoami` | agent id, agent key fingerprint, wallet key fingerprint, paired or not (read-only) |
| `dontaskagain-mcp pair` | send the pairing and wait for the wallet to confirm (up to 10 min) |
| `dontaskagain-mcp --version` | version |

## MCP tools

`wallet_status`, `wallet_preview`, `wallet_request`, `wallet_request_status`, `wallet_cancel`, `wallet_history`.
Each answer is a JSON object plus a short `summary` line for the model.

- `wallet_status` — accounts **with addresses**, names, rules and the address book come only from the view signed by
  the wallet, plus an `e2e` block (`agent_fp`, `wallet_fp`, `paired`). Balances, prices and
  `extension.online/unlocked` come from the Signer operator (not signed by the wallet) and are kept apart in
  `unverified_from_signer`, filtered by an allow-list.
- `wallet_preview` — computed **locally** from the signed view: shape, account binding, allowed types, whether the
  recipient is in the address book. `decision` is always `"human"`: every request waits for the human's signature.
- **Local checks** (`wallet_preview` and before `wallet_request`, nothing is sent when they fail), with the wallet's
  own error codes: `UNSUPPORTED_NETWORK` (served: `tron`, `evm:1`, `evm:42161`, `evm:10`, `evm:137`, `evm:8453`;
  swap on `tron`; USDC bridge between the five EVM networks; refuel `evm:1` → Base / Optimism / Arbitrum),
  `UNSUPPORTED_ASSET`, `BAD_AMOUNT` (USDT, USDC, TRX: 6 decimals; ETH, POL: 18), `INVALID_ADDRESS` (TRON base58check;
  EVM `0x` + 40 hex, EIP-55 checksum when the case is mixed), `SELF_TRANSFER`. The preview also warns
  (`warnings[]`, never a refusal) with `INSUFFICIENT_BALANCE` when the balance the Signer reports (unverified) is lower
  than the amount, and with `NETWORK_NOT_TRUSTED` when the network is not in the wallet's `networks_trusted`.
- `wallet_request` — the request is encrypted and put into the mailbox; the answer waits for the wallet's status
  (`wait_seconds`, default 20). `pending` is normal: the wallet may be closed; the request waits until it opens or
  until `expires_at`. Never repeat a pending request with a new `client_request_id`.
- Status `unknown` (`e2e.no_status_from_wallet: true`) — `expires_at` has passed without a status from the wallet.
  This is **not** "not signed": the operation may have gone through. Do not repeat; check later or ask the human.
- `wallet_history` — only this agent's requests made from this machine.
- Signer errors: the code must match `^[A-Z0-9_]{1,40}$` (otherwise `HTTP_<status>`); the message text is ours, the
  server's own words, if any, go to `error.signer_says_unverified`.
- **Hints.** On errors and on final `failed`/`rejected` with a known `error.code` the answer carries
  `hint: {do, tell_human}` — what the agent should do and what to tell the human — and the same text at the end of
  `summary` (`src/hints.ts`; the server's words never get there).

## Files

| Path | What |
|---|---|
| `$DAA_HOME/agents/<agent_id>.json` | agent private keys, pinned wallet key and `wallet_id`, pairing state; 0600 |
| `$DAA_HOME/agents/<agent_id>.json.old` | previous key after rotation; removed once the new key is paired |
| `$DAA_HOME/state/<agent_id>.json` | request statuses, inbox cursor, ids of accepted envelopes (8 days); 0600 |
| `$DAA_HOME/state/<agent_id>.lock` | lock while writing (several processes of one agent) |

Keys are stored **in plain text**: any process of the same user can read them, including the agent itself.
Permissions are checked strictly — a key or state file that is not ours, not a regular file, or wider than 0600, or a
`DAA_HOME` owned by someone else or writable by others makes the package refuse to work (`E2E_KEY_FILE_PERMS`).
Several processes of one agent (one per client session, plus `whoami`/`pair`) share the files safely under the lock.

## Security in short

- The Signer operator **sees**: wallet and agent ids, your account addresses, size and time of envelopes, IP; a signed
  transaction when it is broadcast (it is public anyway). It does **not** see: type, network, asset, amount,
  recipient, `reason`, `metadata`, decisions, rules, address book, names.
- It **cannot**: sign anything (it has no keys), forge or change an agent request or a wallet answer, roll a status
  back by replaying an old envelope, forward an envelope to another wallet, swap the agent key at pairing (that needs
  the code that goes through the human) or the wallet key (the agent takes it from the command, not from the server).
- It **can**: delay or drop envelopes (the agent then sees `unknown`, not a false `expired`); lie about balances,
  prices and extension state (`unverified_from_signer`) and put any text in an error (`signer_says_unverified`) — both
  are marked unverified.
- Transport: `https` only (except local/private addresses), redirects are not followed, answers ≤ 4 MiB, a timeout on
  every request.
- Out of scope: a compromised agent machine (key + token = the agent's rights; revoke with one button in the wallet).

## Rotation and revocation

- **New agent key**: "Reconnect" in the wallet (new token and code) → replace the command. Seeing a new `DAA_PAIR`
  with an already paired key, the package keeps the old key as `.old`, creates a new one and pairs again.
- **New wallet key** (the human changed the encryption key): every agent reconnects with a new command. If
  `DAA_WALLET` changes **without** a new code, the package refuses to work (`E2E_WALLET_KEY_CHANGED`) — it may be a
  tampered configuration.
- **Revoke**: in the wallet, immediately; envelopes from a revoked agent are not accepted.

## Development

```bash
npm ci
npm run typecheck
npm test          # builds, then crypto against reference vectors + flows with a fake mailbox and a fake extension
npm pack          # local archive
```

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 FOXOKO LABS LTD.
