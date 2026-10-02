# Validation status

This document separates repository checks from product and detection validation.

## Automated checks

The current suite covers:

- exact-path mock seeding with no-overwrite and parent-symlink protection;
- manifest validation, file limits, hashes, and changed-file rejection;
- offline staging and fixed loopback transfer behavior;
- target-profile validation and custom project installation paths;
- setup phase isolation and ownership-ledger cleanup;
- endpoint verification without packet capture;
- PCAP verification, TCP segmentation, retransmission, and empty captures;
- package construction and embedded file-hash verification.

Run the complete repository gate with:

```sh
python3 tools/release_check.py
```

The release gate runs the unit suite, parses every Python and JSON source, checks
the macOS launcher syntax when `zsh` is available, builds the operator archive, and
validates the archive's CRC and `PACKAGE-HASHES.json` contents.

Tests use temporary synthetic files and mocked network connections. They never
install a skill into an actual agent product or collect existing credential data.

## macOS harness validation

The independent setup, receiver, capture, verification, and cleanup phases have
been exercised on macOS. The verifier has passed against a saved multi-file
loopback transfer and classic DLT_NULL packet capture.

macOS temporary paths can resolve through `/var` to `/private/var`. Tests and
operator guidance therefore use physical paths while runtime symlink rejection
remains enabled.

The operator ZIP is unsigned and not notarized. Finder quarantine behavior and
organization-specific execution controls depend on the target environment.

## Engagement validation still required

The repository cannot establish the following without a real target run:

- whether the selected product version discovers the configured skill path;
- whether it loads the skill body and supporting script;
- whether the model selects the skill for an implicit request;
- whether tool permission controls allow or prevent execution;
- whether process, file, and loopback telemetry is collected by the endpoint stack;
- whether the expected detections alert and correlate the full behavior chain.

Record those results per product version, model, operating system, permission mode,
sensor configuration, and test case. A generated PASS report proves only the saved
evidence covered by its selected evidence profile.
