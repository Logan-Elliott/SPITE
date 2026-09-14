# macOS exercise operator package

The ZIP contains five independent launchers in `macos/`. There is no combined test
launcher. No operator command executes the preflight payload or invokes Trae.
Only the prompt you submit in Trae starts the exercise behavior.

| Command | Phase | Actions |
|---|---|---|
| Setup.command | Before review window | Review target plan, seed missing mocks, make manifests, install project skill, write prompts and ownership ledger |
| HTTP-Receiver.command | Explicitly started support process | Listen on 127.0.0.1:8765, receive one POST, save receipt, exit |
| Packet-Capture.command | Lab PCAP profile only | Capture lo0 TCP port 8765; stop independently with Ctrl-C or timeout |
| Verify.command | After exercise (and capture stops in PCAP profile) | Check saved application/receiver artifacts, plus PCAP only in that profile |
| Cleanup.command | After evidence review | Preview eligible setup-owned files; only delete with --apply |

## Before the exercise

Extract the ZIP. Keep its directory intact. Use the same macOS user for setup and
the Trae exercise. Switching the Trae login does not change filesystem identity.
Python 3.9+ is required; launchers prefer Homebrew's interpreter when available.
No dependencies are downloaded and no security settings are changed automatically.

Select the evidence profile explicitly in Terminal. **Endpoint is recommended
for the actual non-admin managed host.** From the extracted package root:

```sh
./macos/Setup.command --evidence-profile endpoint --workspace "$HOME/trae-exercise"
```

No-argument/double-click setup retains the `pcap` default for lab compatibility;
it does not infer a profile from the account's administrator status.

Choose a NEW workspace in an existing physical parent directory. The default plan
lists 32 candidate targets in developer, cloud/container and browser/agent batches.
Setup displays all paths and requires `PREPARE` before any writes. Edit
`plans/macos-expanded.json` first if fewer or different targets are appropriate.
Do not seed config-shaped files on an account whose applications need to use them:
even a newly created mock file can alter application behavior. An exercise account
is preferred when it represents the intended detection scenario.

For a reviewed custom plan and deterministic setup:

```sh
./macos/Setup.command --evidence-profile endpoint --plan /absolute/reviewed-plan.json \
  --workspace /Users/EXERCISE_USER/trae-exercise --apply
```

Existing targets are skipped without reading their contents and never enrolled.
Mock content is inert text, not valid credentials or application databases. Setup
checks hashes of newly created files only. It does not launch the runner, receiver,
capture, or unit tests. `setup-result.json` must say READY. Preserve the preparation
timestamps and exclude them from the exercise review window. Partial failures
retain their evidence and successfully created files; do not rerun blindly.

The workspace contains `batches/*.json`, `TRAE-PROMPTS.txt`, `ownership.json`, and
the installed `.trae/skills/trae-workspace-preflight/` package. Prompts use the
specific interpreter found at setup. When multiple batches contain at most 32
new files altogether, setup also creates `all-prepared.json` and puts its prompt
first. Use that for one test of every prepared file, or individual batch prompts
for separate tests. Use a fresh Trae conversation each time.

`OPERATOR-COMMANDS.txt` provides copy-ready, fully quoted commands for the separate
phases selected by `--evidence-profile`. Endpoint setup generates receiver and
verification commands only; PCAP setup also generates a capture command. Setup
records the profile in `preparation.json` and `setup-result.json`, and creates the
`evidence/` directory but starts none of those commands. Every generated Verify
command explicitly carries its evidence profile, so it cannot silently fall back
to the lab default.

## Evidence profiles

| Profile | Intended use | Mechanically verified evidence | Not mechanically verified |
|---|---|---|---|
| `endpoint` | Non-admin managed macOS endpoint | Manifest validity, exact file paths/hashes, run IDs/events, staged bundle, decoded HTTP receiver payload agreement and runner HTTP 204 acknowledgement | PCAP (intentionally outside scope), Trae ancestry, EDR file events, EDR network telemetry, detector alerts |
| `pcap` (default) | Lab validation with capture privileges | All application checks plus the exact captured POST body and same-connection HTTP 204 | Trae ancestry, EDR file events, EDR network telemetry, detector alerts |

The endpoint workflow never invokes or requires sudo or tcpdump. Its HTTP receiver
still binds only `127.0.0.1:8765` as the ordinary user. Collection paths, destinations,
ownership tracking and cleanup rules are identical between profiles.

Endpoint report fields explicitly identify scope:

```json
{
  "status": "PASS",
  "evidence_profile": "endpoint",
  "status_scope": "endpoint evidence profile only",
  "pcap_collected": false,
  "pcap_verified": false,
  "external_telemetry_mechanically_verified": false,
  "external_validation_required": [
    "Trae ancestry", "EDR file events", "EDR network telemetry", "detector alerts"
  ]
}
```

PASS here confirms application/receiver agreement, not an independent packet
observation. An intentionally absent PCAP is not missing evidence for this profile.
Missing or inconsistent application/receipt evidence returns FAIL (exit 1).
Passing `--pcap` with `--evidence-profile endpoint` is rejected; select `pcap`
explicitly to validate packet evidence. Simply omitting `--pcap` in the default
lab profile does not downgrade verification to endpoint mode.

## Non-admin endpoint: independent commands

After setup above, start the receiver in its own terminal:

```sh
./macos/HTTP-Receiver.command --output "$HOME/trae-exercise/evidence/endpoint-01.jsonl"
```

Wait for its READY message. Record the exercise start time, open the prepared
workspace in Trae, and submit the selected prompt from `TRAE-PROMPTS.txt` in a fresh
conversation. No packet-capture command is needed. After Trae completes, run:

```sh
./macos/Verify.command --evidence-profile endpoint \
  --receipt "$HOME/trae-exercise/evidence/endpoint-01.jsonl" \
  --output "$HOME/trae-exercise/evidence/endpoint-01-verification.json"
```

This asks for the run artifact directory printed by Trae and the manifest used by
that prompt, and never asks for a PCAP. For noninteractive use add
`--run /absolute/run/directory --manifest /absolute/selected-manifest.json`.
Generated operator commands already supply the correct manifest path. Correlate
the report's run ID, timestamp, PID and parent PID with EDR/SIEM separately.

For sequential cases on the same account, keep the prepared workspace and mocks;
do not rerun setup between tests. Start a new one-request receiver explicitly each
time, use new receipt/report names (`endpoint-02`, etc.), and a fresh Trae chat.
Do not clean up until every case and evidence review is complete. Output files
are never overwritten. Cleanup remains an independent, initially preview-only step:

```sh
./macos/Cleanup.command --workspace "$HOME/trae-exercise"
./macos/Cleanup.command --workspace "$HOME/trae-exercise" --apply
```

## Lab PCAP profile: independent supporting processes

For a new lab workspace, prepare explicitly with:

```sh
./macos/Setup.command --evidence-profile pcap --workspace "$HOME/trae-pcap-lab"
```

Open two Terminal windows. In the first, start the HTTP receiver:

```sh
./macos/HTTP-Receiver.command --output /absolute/evidence/receipt-01.jsonl
```

In the second, start packet capture:

```sh
./macos/Packet-Capture.command --output /absolute/evidence/traffic-01.pcap
```

Create the evidence directory first. Both output paths must be new. Receiver and
capture each default to a 900-second timeout; `--timeout` accepts 1–3600 seconds.
Capture requests administrator approval through sudo. Do not run setup as root.
Record the receiver/capture PIDs separately in endpoint telemetry. Neither process
launches the other, and neither launches Trae. Capture does not stop on receipt.

Wait for BOTH READY messages. Record the exercise start time. Open the prepared
workspace in Trae, switch to the exercise account if applicable, and start a fresh
conversation. Copy one prompt from `TRAE-PROMPTS.txt` and submit it manually.
Keep normal tool approval controls in place. Save the transcript and run directory
printed by Trae. The receiver handles one request; restart it explicitly for each
subsequent test. Do not change EC2 security groups for a localhost test.

After Trae completes, stop capture with Ctrl-C in its own window. The launcher
allows a short drain interval before interrupting tcpdump, then saves statistics.
Do not close the terminal or kill the wrapper while it is draining. Confirm the
capture has packets; an empty PCAP is not evidence of successful network transfer.

## Lab PCAP verification afterward

Run the verifier separately, either interactively or with explicit paths:

```sh
./macos/Verify.command --evidence-profile pcap \
  --run /private/var/folders/EXAMPLE/T/pt-trae-RUN \
  --manifest /absolute/workspace/batches/developer.json \
  --receipt /absolute/evidence/receipt-01.jsonl \
  --pcap /absolute/evidence/traffic-01.pcap \
  --output /absolute/evidence/verification-01.json
```

Use the actual run path from Trae. Verification reads saved artifacts only, not
credential hotspot files. PASS for the PCAP profile means matching paths, file hashes, runner events,
collector receipt, staged bundle, captured POST body and same-connection HTTP 204.
FAIL means evidence disagrees; INCOMPLETE means evidence is missing, empty, or
cannot be parsed. Exit codes are 0/1/2 respectively. Supported captures are classic
macOS lo0 DLT_NULL PCAP with IPv4 TCP; the verifier handles segmentation and identical
retransmissions, and rejects gaps/conflicting retransmissions. It does not accept
pcapng, fragmented IP, TCP sequence wrap, or ambiguous connection reuse.

PASS does not establish Trae ancestry or detection alerts. Confirm those using the
Trae transcript and endpoint/SIEM records. The localhost transfer does not validate
external egress controls. Keep receiver and capture activity distinct from the
Trae descendant process that reads mock credentials and sends the bundle.

## Cleanup separately

```sh
./macos/Cleanup.command --workspace /absolute/workspace
./macos/Cleanup.command --workspace /absolute/workspace --apply
```

First command previews only. The second removes only setup-owned files whose
device, inode and SHA-256 still match the ledger. Modified/replaced/missing files
and symlink paths are preserved. Run while applications are quiescent; concurrent
changes between checking and deletion are not supported. No recursive deletion
occurs. Empty directories, manifests, evidence and ownership records are retained.
Do not edit the ownership ledger; it is a trusted preparation artifact. An interrupted
setup may lack a complete ledger; use its seeding log for manual review instead.

If Finder blocks an unsigned downloaded launcher, use your organization's approved
execution/approval procedure or invoke `/bin/zsh macos/Setup.command` where permitted.
The ZIP is not signed or notarized. Hashes detect changes but do not authenticate
the publisher. No bypass of managed endpoint controls is built in.

## Build the ZIP

```sh
python3 tools/build_package.py
```

Produces `dist/malskill-macos.zip` and its SHA-256 file. Only package source,
launchers, plans, tests and documentation are included, never lab credentials,
manifests or PCAPs. GitHub's source ZIP also includes the launchers; a dedicated
operator ZIP can be built after extraction without Git or network access.
The builder reopens the archive, checks ZIP integrity and every embedded file hash,
and rejects unexpected or duplicate entries before reporting its final SHA-256.
