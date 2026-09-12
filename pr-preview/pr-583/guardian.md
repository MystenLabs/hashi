# Guardian

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> The withdrawal Guardian is a second signatory on managed Bitcoin deposits, providing defense in depth against committee compromise.

To protect against vulnerabilities and against malicious past committees,
Hashi uses a withdrawal guardian: a second signatory on the managed Bitcoin
deposits. All deposits are spendable only with a 2-of-2 multisig where the
guardian is one party and the Hashi MPC committee is the other.

Additional details about the guardian integration are added before Testnet.
