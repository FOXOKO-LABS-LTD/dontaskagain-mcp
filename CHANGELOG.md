# Changelog

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
