# Loon security posture

This repository must stay safe to publish. Do not commit full `.lcf` files,
proxy nodes, remote proxy subscription URLs, certificates, passphrases, API
tokens, or MITM hostnames.

## Account-risk posture

- Prefer stable routing over fastest-node switching for finance, crypto,
  payment, social, and streaming accounts.
- Keep mainland实名 services on `DIRECT` unless there is a specific reason to
  proxy them.
- Keep PayPal separate from the broader finance/crypto group so it can use a
  dedicated stable exit.
- Avoid MITM/rewrite plugins for authenticated app business traffic. DNS and
  HTTPDNS hygiene are lower risk than request-body/header rewriting.
- Treat ad blocking and app enhancement plugins as optional. Disable them first
  when login, playback, payment, captcha, or account-risk signals appear.

## Public artifacts

Safe to publish:

- Domain rule lists under `rules/loon/`.
- Routing-order documentation.
- Validation and secret-audit tooling.

Unsafe to publish:

- `[Proxy]`, `[Remote Proxy]`, and complete `[Mitm]` material.
- Node names if they reveal subscription/provider identity.
- Subscription URLs or URLs with token-like query parameters.
- Certificates, passphrases, private keys, cookies, or account identifiers.

## Local Loon policy

Use this order for self-maintained rules before broad third-party catchalls:

1. `AccountSafety-DIRECT` -> `DIRECT`.
2. `Seetong-Local` -> `Seetong`.
3. `PayPal-Stable` -> `PayPal`.
4. `FinanceCrypto-Stable` -> `金融加密`.
5. `AI-Reconnect` -> `AI`.

These rules are intentionally small. Broad coverage should come from reviewed
external rules after service-specific local safety rules have had priority.
