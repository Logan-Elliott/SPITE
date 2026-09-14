# Current revision: pre-seeded macOS mock files

## Endpoint evidence profile

Testing is confined to the repository
and temporary synthetic test directories. No real Trae payload was invoked;
existing runner unit tests use temporary mock files and mocked network connections.

The complete suite passes 28 tests on the Linux development host. New regression
coverage verifies endpoint setup emits no capture/sudo/tcpdump command, records its
profile, still generates the receiver, and supplies an explicit no-PCAP Verify
command. Endpoint verification passes with valid synthetic application evidence
and no PCAP or PCAP prompt; missing artifacts, bad receipt run IDs, wrong hashes,
wrong paths, invalid manifests and failed HTTP acknowledgements fail. Endpoint
setup, receiver and verifier tests reject subprocess execution. Existing PCAP,
ownership and cleanup tests remain passing, and explicit PCAP verification still
requires packet evidence. Profile reports list external EDR/SIEM checks as not
mechanically verified.

The package is rebuilt with endpoint and lab operator instructions and checked for
ZIP CRC integrity and agreement with every embedded PACKAGE-HASHES.json entry.
Native execution on the specified managed macOS version, Trae discovery/tool
permissions and external EDR/SIEM detections still require target-side validation.

## Independent macOS operator package — September 13, 2026

The operator package separates setup, HTTP receiving, packet capture, artifact
verification and explicit cleanup. The operator CLI never invokes the payload.
Its tests cover setup ownership and phase isolation, changed-file cleanup,
combined manifests, TCP segmentation/retransmission, real runner artifact
verification and the empty-PCAP failure case. The packaged setup/cleanup launchers
passed in an isolated macOS workspace. Receiver and capture startup/timeouts were
checked independently without executing the payload. The packaged verifier also
returned PASS against the saved 29-file, 7,828-byte transfer and 14-packet capture
from run `e566aac6-6454-407b-9342-2f4385df667b`.

Finder quarantine handling and managed-device execution controls have not been
validated; the ZIP is unsigned. Operator verification does not validate EDR alerts.

## macOS lab test-path fix — September 13, 2026

The first macOS lab run on Python 3.14.3 reported two failures and three errors.
Preflight tests used `/var/folders/...` paths whose parent is a symlink; the runner
correctly rejected those paths before reaching the intended test behavior.
The exact failure pattern was reproduced on Linux using a symlinked TMPDIR.
The test helper now resolves its temporary root before registering fixtures.
All 13 tests pass with both ordinary and symlinked temporary roots on Linux,
including a new regression test. Runtime symlink rejection remains unchanged.
Confirmation of the corrected suite on the macOS lab host is still pending.

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
