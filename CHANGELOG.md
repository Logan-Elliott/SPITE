# Changelog

All notable changes to this project are documented here.

## Unreleased

- Renamed the project to SPITE: Skill Poisoning and Instruction Trust
  Evaluation. The command is now `spite`; install paths, exercise markers,
  receiver protocol names, private state folders, generated text, release
  archives, and repository automation use the SPITE name.
- Replaced the fixed `PurpleTeam`/`purple-team` browser profile segments with
  cross-platform placeholders (`<chrome-profile>`, `<brave-profile>`,
  `<edge-profile>`, `<firefox-profile>`, `<trae-storage>`, `<openclaw-config>`,
  `<openclaw-home>`) that setup resolves on macOS or Linux. Discovery honors
  `XDG_CONFIG_HOME` and checks native, snap, and flatpak roots for Chrome,
  Chromium, Brave, Edge, and Firefox. Synthetic setup keeps an isolated
  `~/.spite-exercise/` namespace so it never writes into a real profile.
- Pointed the Trae browser-agent target at the real `state.vscdb` secret store
  and raised the real-harvest size limit to 8 MiB per file and 8 MiB total so
  browser and Trae credential stores are collected.
- Listed both the modern `Network/Cookies` and the legacy profile-root `Cookies`
  paths for Chrome, Brave, and Edge so flatpak and older Chromium builds are
  collected on Fedora and other distributions.

## 0.2.0 - 2026-10-02

- Added an operator choice between synthetic files and real harvest:
  `spite init --harvest real` selects existing files from the file list, records
  their hashes, and sends their contents in the bundle. Setup never creates,
  changes, or deletes real files, and cleanup preserves them. The default
  remains synthetic.
- Added operator-configurable transfer destinations: `spite init --destination`
  accepts an `http`, `https`, `ws`, or `wss` URL, the generated prompt uses
  `--send-to`, and verification checks the transfer acknowledgement against
  the saved destination.
- Kept the localhost receiver test as the default; `https` and `wss` transfers
  verify certificates, follow no redirects, and send only the manifest-verified
  bundle.
- Kept the standard synthetic test on credential-shaped macOS paths so endpoint
  detections see the locations they are intended to monitor.
- Moved authoritative cleanup state outside the agent workspace, added
  incremental setup records, and listed every path before removal.
- Added bundle-digest acknowledgements, offline verification, per-test-case
  report states, and the `ARTIFACTS VERIFIED` result.
- Matched the benign control to the normal file, manifest, metadata, and prompt
  conditions.
- Added self-contained installation, update and uninstall commands, `spite
  doctor`, and an engagement report template.
- Added a tag-driven release workflow with pinned actions and GitHub artifact
  attestations.

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
- Added the `spite` command with init, receive, verify, capture, clean, install, and
  version subcommands; retained the macOS launchers for compatibility.
