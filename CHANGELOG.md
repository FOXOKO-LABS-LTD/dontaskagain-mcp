# Changelog

## 0.1.5 — 2026-11-25
- Local checks in `wallet_preview` and before `wallet_request` (nothing is sent when they fail), with the wallet's
  error codes: `UNSUPPORTED_NETWORK` (a network or an operation the wallet does not serve, an account without an
  address there), `UNSUPPORTED_ASSET`, `BAD_AMOUNT` (more decimals than the asset has: USDT, USDC, TRX 6; ETH, POL 18;
  zero), `INVALID_ADDRESS` (TRON base58check; EVM `0x` + 40 hex with the EIP-55 checksum when the case is mixed),
  `SELF_TRANSFER`. Before 0.1.5 such a request reached the wallet and failed only in the human's window.
- `wallet_preview` warns, never refuses: `INSUFFICIENT_BALANCE` when the balance reported by the Signer (not signed
  by the wallet) is lower than the amount, `NETWORK_NOT_TRUSTED` when the network is not in `networks_trusted`.
- Hints (`hint.do`, `hint.tell_human`) for `INVALID_ADDRESS`, `BAD_AMOUNT`, `UNSUPPORTED_NETWORK`,
  `UNSUPPORTED_ASSET`, `SELF_TRANSFER`, `INSUFFICIENT_BALANCE`, `NOT_CANCELLABLE`, `BAD_REQUEST`.
- README: install from npm (`npx -y dontaskagain-mcp@0.1.5`); the website archive is the fallback.

## 0.1.4 — 2026-11-25
- First version published from the public repository. Source comments no longer point to documents that are not
  public; `prepublishOnly` checks the package before it is published.
- Legacy aliases of the URL and token variables are gone: use `DAA_URL` / `DAA_TOKEN` (or `DAA_CONFIG`).

## 0.1.3 — 2026-11-24
- Hints for the model and for the human on known error codes (`AGENTS_PAUSED`, `BUILD_FAILED` incl. network timeout,
  `INSUFFICIENT_GAS`, `INVITE_REQUIRED`, `RATE_LIMITED`, `DECISION_NOT_ALLOWED`, …): `hint.do` and `hint.tell_human`
  in tool answers and at the end of `summary`. After a final `BUILD_FAILED`, retry with a new `client_request_id`.

## 0.1.2 — 2026-11-23
- The wallet never signs on its own: `wallet_preview` always answers `decision: "human"`; no `auto_signed` status.

## 0.1.1 — 2026-11-20
- Security hardening after an external audit: only data signed by the wallet is trusted, Signer text is kept apart
  and marked unverified, monotonic statuses, strict tool arguments, multi-process safe key and state files, strict
  file permissions, https-only transport without redirects.
- `DAA_CONFIG`: secrets in a mode-600 file instead of the command line. Exact version in the npx command.
- Node ≥ 20.19.

## 0.1.0 — 2026-11-19
- First version: end-to-end encrypted agent side (`daa-e2e-1` envelopes), agent key file, pairing with the wallet,
  Signer mailbox client, stdio MCP tools `wallet_status`, `wallet_preview`, `wallet_request`,
  `wallet_request_status`, `wallet_cancel`, `wallet_history`.
