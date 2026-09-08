# Current revision: pre-seeded macOS mock files

The separate seeding tool adds six tests covering missing-file creation and
permissions, existing content/metadata preservation, directories and dangling
symlinks, symlinked parents, a concurrent creator, and invalid paths. All 12 tests
pass on the Linux development host. Seeding remains outside the skill workflow.

Six unit tests passed on the Linux development host: unchanged pre-seeded files,
missing files without creation, changed files excluded from staging/transfer,
symlink rejection, mocked loopback transfer, and transfer failure reporting.
Tests seed their isolated inputs before invoking the runner; the runner does not
seed them. Existing input content and modification timestamps are checked.
Actual macOS/Trae behavior and detector alerts remain untested. The actual socket
exchange below was for the earlier runtime-seeding revision, not this revision.

# Earlier revision validation — September 8, 2026

- Three unit tests passed: offline evidence, fixed loopback destination and payload,
  and transfer failure without false completion.
- Main skill frontmatter passed the skill-creator validator.
- Actual sender/collector exchange passed: HTTP 204, collector received synthetic
  data, sender exited 0, and the one-request collector exited 0.
- Successful run ID: `005f340b-8047-42ab-b7f0-9ab6d4ef1b19`.
- Evidence directory on this host: `/tmp/pt-trae-xw1f52cq`.
- Initial sandboxed socket attempt was blocked and correctly produced
  `transfer_failed` with exit 1. Evidence: `/tmp/pt-trae-xjypnxds`.
  Local socket verification was then completed with approved escalation.

These were harness tests launched from the terminal. No Trae installation,
skill-loading behavior, model response, EDR alert, or SIEM correlation was tested.
The included detection guidance remains a set of hypotheses for endpoint testing.
