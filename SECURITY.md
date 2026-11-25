# Security policy

This code holds or handles wallet keys and signed transactions, so we take reports seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

- Use GitHub private vulnerability reporting: the **Security** tab of this repository → **Report a vulnerability**
  (https://github.com/FOXOKO-LABS-LTD/dontaskagain-mcp/security/advisories/new), or
- email **security@dontaskagain.xyz**.

Include the affected version, the steps to reproduce and the impact you see. We acknowledge reports within a few
working days, keep you informed while we fix the issue and credit you in the advisory unless you ask us not to.

## Scope

- The code in this repository and the release artifacts built from it (published on https://dontaskagain.xyz/dl/).
- The public Signer operated by FOXOKO LABS LTD is in scope for reports about the protocol as seen from this
  code. Please do not run load tests, spam or automated scanning against it.

Out of scope: a compromised machine of the human or of the agent, social engineering, and third-party services
(RPC providers, bridges, DEXes) unless this code uses them unsafely.

## Supported versions

Only the latest released version gets security fixes.
