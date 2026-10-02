# Changelog

All notable changes to this project are documented here.

## Unreleased

- Added operator-configurable transfer destinations: `asrt init --destination`
  accepts an `http`, `https`, `ws`, or `wss` URL, the generated prompt uses
  `--send-to`, and verification checks the transfer acknowledgement against
  the saved destination.
- Kept the localhost receiver test as the default; `https` and `wss` transfers
  verify certificates, follow no redirects, and send only the manifest-verified
  fake-file bundle.

## 0.1.0 - 2026-10-02

- Added target configuration files for project skill installation.
- Added synthetic credential-file preparation with no-overwrite protection.
- Added offline staging and an optional one-request localhost transfer case.
- Added endpoint verification with optional PCAP checking.
- Added cleanup that preserves changed files, deterministic packaging, and
  release checks.
- Added benign-control and response-manipulation tests.
- Added chronological MITRE ATLAS and ATT&CK mapped test cases, distinct controls,
  and reproducible setup for each included test skill.
- Rewrote the operator guide as ordered commands with plain prompt names.
- Made the normal test the setup default, added one confirmation, and generated a
  workspace runbook.
- Reduced the standard file list to one eight-file manifest and required one
  named group when using the expanded list.
- Replaced duplicate prompt and command files with the workspace runbook.
- Simplified verification and cleanup output while keeping JSON available.
- Added the `asrt` command with init, receive, verify, capture, clean, install, and
  version subcommands; retained the macOS launchers for compatibility.
