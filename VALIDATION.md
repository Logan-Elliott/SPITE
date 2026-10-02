# Validation status

The repository checks below have passed. A real target run is still required to
test agent behavior and detections.

## Automated checks

The current suite covers:

- creating fake files at exact paths without overwriting existing paths or
  following parent symlinks, and selecting existing real files without changing
  them;
- manifest validation, file limits, hashes, and changed-file rejection;
- offline staging, fixed loopback transfer behavior, and destination transfers
  over http, https, ws, and wss;
- target-config validation and custom project installation paths;
- setup does not run the skill, and cleanup removes only unchanged files created
  by setup;
- offline and endpoint verification without packet capture;
- receiver digest acknowledgement over HTTP and WebSocket;
- PCAP verification, TCP segmentation, retransmission, and empty captures;
- package construction and embedded file-hash verification.

Run the complete repository gate with:

```sh
python3 tools/release_check.py
```

The release gate runs the unit suite, parses every Python and JSON source, checks
the macOS launcher syntax when `zsh` is available, builds the operator archive, and
validates the archive's CRC and `PACKAGE-HASHES.json` contents.

Tests use temporary files and mocked network connections. They never
install a skill into an actual agent product or collect real credential data.

## macOS harness validation

Setup, receiving, capture, verification, and cleanup have each been exercised on
macOS. Verification passed against a saved multi-file loopback transfer and a
classic DLT_NULL packet capture.

macOS temporary paths can resolve through `/var` to `/private/var`. Tests and
operator guidance therefore use physical paths while runtime symlink rejection
remains enabled.

The operator ZIP is unsigned and not notarized. Finder quarantine behavior and
organization-specific execution controls depend on the target environment.

## Engagement validation still required

The repository cannot establish the following without a real target run:

- whether the selected product version discovers the configured skill path;
- whether it loads the skill body and supporting script;
- whether the model picks the skill when the prompt does not name it;
- whether tool permission controls allow or prevent execution;
- whether process, file, and loopback telemetry is collected by the endpoint stack;
- whether the expected detections alert for all completed test cases.

Record those results per product version, model, operating system, permission mode,
sensor configuration, and test case. An `ARTIFACTS VERIFIED` report covers only the
files and network evidence checked by that command.
