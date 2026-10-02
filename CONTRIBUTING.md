# Contributing

Use an issue to describe operator-facing changes before starting a large pull
request. Security reports belong in the private process described in
[SECURITY.md](SECURITY.md), not in a public issue.

Keep the default exercise safe for an authorized, dedicated test account. Do not
add live credentials, captured engagement data, remote payload downloads,
persistence, or destructive behavior. Tests must use temporary synthetic data or
a purpose-built test VM.

Before opening a pull request:

1. Add or update tests for every behavior change.
2. Run `python3 tools/release_check.py`.
3. Explain what an operator sees and how you tested it.
4. Do not commit generated archives, credentials, receipts, PCAPs, or run folders.

Use plain operator wording and keep commits focused.
