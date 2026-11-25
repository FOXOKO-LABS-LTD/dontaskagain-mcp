// Hints for the model: what an error code means for the agent and what to tell the human (0.1.3).
// Our own text only — never the Signer's words. The protocol has no hint field: the
// hint goes into this package's tool answer next to `summary` (`hint.do`, `hint.tell_human`) and into the summary.

export interface Hint { do: string; tell_human: string }

const H: Record<string, Hint> = {
  AGENTS_PAUSED: {
    do: 'The human paused all agents of this wallet. Do not retry and do not create new requests until the human says the pause is over.',
    tell_human: 'All agents are paused in your Don\'t Ask Again wallet. If you want me to continue, turn the pause off in the extension and tell me.',
  },
  BUILD_FAILED: {
    do: 'The wallet could not build the transaction (nothing was signed or sent). Do not loop: tell the human; send it again (with a new client_request_id) only after the human says the cause is fixed.',
    tell_human: 'The wallet could not prepare this transaction, so nothing was signed or sent. Open the extension to see the reason; if it is a network problem, check that the wallet can reach the network and ask me to try again.',
  },
  BUILD_FAILED_TIMEOUT: {
    do: 'The wallet could not reach the network in time ("signal timed out"); nothing was signed or sent. Do not loop: tell the human; after they fix it, send the request once more with a new client_request_id (the old one is final).',
    tell_human: 'Your wallet could not reach the blockchain network in time, so nothing was signed or sent. Check the internet connection and the network (node) access of the extension, or turn on Settings → End-to-end encryption → "Read everything through the Signer" in the extension (the Signer operator then sees recipients and estimated amounts). Then tell me to try again.',
  },
  INSUFFICIENT_GAS: {
    do: 'Not enough native coin for gas on that network (detail: network, need_native, have_native). Never buy gas yourself. If detail.refuel_hint is present you may offer that refuel intent; for a bridge with delivery "self" you may retry with delivery "forwarding".',
    tell_human: 'There is not enough of the network\'s native coin (gas) on this account. Please top it up (or let me request a refuel from Ethereum if one is offered), then I will try again.',
  },
  INVITE_REQUIRED: {
    do: 'The public Signer accepts new wallets by invitation only. You cannot register yourself: only the human can request access and create the wallet.',
    tell_human: 'The public Signer works by invitation. Request access at https://dontaskagain.xyz/#access with your email or Telegram username; the invitation comes to that contact.',
  },
  INVITE_INVALID: {
    do: 'The invitation code is unknown, expired, revoked or used. Only the human can get a new one.',
    tell_human: 'The invitation code did not work (unknown, expired or already used). Request a new one at https://dontaskagain.xyz/#access.',
  },
  RATE_LIMITED: {
    do: 'Too many calls. Wait retry_after seconds (or at least a minute), then retry the same call with the same client_request_id. Do not create new requests meanwhile.',
    tell_human: 'I am sending requests too often; I will wait a moment and continue.',
  },
  TOO_MANY_PENDING: {
    do: 'You have 20 pending requests. Wait for the human to answer them or cancel the ones you no longer need (wallet_cancel). Do not create new ones.',
    tell_human: 'There are many of my requests waiting for your signature. Please review them in the extension.',
  },
  DECISION_NOT_ALLOWED: {
    do: 'Only the human can decide: the wallet never signs on its own. There is no way around it; wait for the human\'s signature.',
    tell_human: 'This wallet never signs on its own: every transaction waits for your signature in the extension window.',
  },
  REJECTED_BY_HUMAN: {
    do: 'The human rejected the request. This is an answer, not an error: do not resend it unchanged.',
    tell_human: 'You rejected the request; tell me if you want something changed.',
  },
  TYPE_NOT_ALLOWED: {
    do: 'This operation type is not allowed for you. You cannot add it yourself.',
    tell_human: 'I am not allowed to request this type of operation. If you want me to, allow it in the extension: agent settings → allowed types.',
  },
  ACCOUNT_NOT_ALLOWED: {
    do: 'This account is not bound to you. You cannot bind it yourself.',
    tell_human: 'I am not connected to this account. If you want me to use it, add it to my agent settings in the extension.',
  },
  ACCOUNT_NOT_BOUND: {
    do: 'This account is not bound to you. You cannot bind it yourself.',
    tell_human: 'I am not connected to this account. If you want me to use it, add it to my agent settings in the extension.',
  },
  UNAUTHORIZED: {
    do: 'The Signer does not accept your token (revoked or reconnected). Stop calling the wallet.',
    tell_human: 'My connection to your wallet no longer works. Reconnect me in the extension ("Connect agent") and update my configuration.',
  },
  AGENT_REVOKED: {
    do: 'Your token was revoked or reissued. Stop calling the wallet.',
    tell_human: 'My access to your wallet was revoked or reissued. If you want me back, reconnect me in the extension ("Connect agent").',
  },
  WALLET_BLOCKED: {
    do: 'The wallet is blocked on this Signer. Stop calling it.',
    tell_human: 'Your wallet is blocked on the public Signer. Contact the operator through https://dontaskagain.xyz/.',
  },
  E2E_VIEW_NOT_SYNCED: {
    do: 'The wallet has not published its data for you yet. Wait; do not create requests until wallet_status shows accounts.',
    tell_human: 'Please open the Don\'t Ask Again extension and unlock it, so it can finish connecting me.',
  },
  MAILBOX_FULL: {
    do: 'The wallet mailbox is full. Wait for the human to open the extension.',
    tell_human: 'Please open the Don\'t Ask Again extension: my messages are waiting for it.',
  },
  RESOURCE_UNAVAILABLE: {
    do: 'TRON resources could not be bought, nothing was sent. Report it; do not loop.',
    tell_human: 'The wallet could not buy TRON energy/bandwidth for this transfer right now, so nothing was sent. We can try again later.',
  },
  UNAVAILABLE: {
    do: 'The Signer cannot be reached. Retry later with the same client_request_id.',
    tell_human: 'I cannot reach the wallet\'s Signer right now; I will try again later.',
  },
  E2E_NOT_CONFIGURED: {
    do: 'The MCP server is not configured (DAA_CONFIG or DAA_* variables). You cannot fix it yourself.',
    tell_human: 'My wallet connection is not set up. In the extension use "Connect agent" and follow its steps on this machine.',
  },
};

/** The hint for an error code; `message` (our own or the wallet's) refines BUILD_FAILED. */
export function hintFor(code: unknown, message?: unknown): Hint | undefined {
  const c = String(code ?? '');
  if (c === 'BUILD_FAILED' && /timed?\s*out|timeout/i.test(String(message ?? ''))) return H.BUILD_FAILED_TIMEOUT;
  return Object.prototype.hasOwnProperty.call(H, c) ? H[c] : undefined;
}

/** Adds `hint` to a tool answer and its text to `summary`. */
export function withHint<T extends Record<string, any>>(out: T, code: unknown, message?: unknown): T {
  const h = hintFor(code, message);
  if (!h) return out;
  return { ...out, hint: h, summary: `${out.summary ?? ''} — ${h.do} Tell the human: "${h.tell_human}"`.replace(/^ — /, '') };
}

export const HINT_CODES = Object.keys(H);
