# macOS exercise operator package

The ZIP contains five independent launchers in `macos/`. There is no combined test
launcher. No operator command executes the preflight payload or invokes Trae.
Only the prompt you submit in Trae starts the exercise behavior.

| Command | Phase | Actions |
|---|---|---|
| Setup.command | Before review window | Review target plan, seed missing mocks, make manifests, install project skill, write prompts and ownership ledger |
| HTTP-Receiver.command | Explicitly started support process | Listen on 127.0.0.1:8765, receive one POST, save receipt, exit |
| Packet-Capture.command | Explicitly started support process | Capture lo0 TCP port 8765; stop independently with Ctrl-C or timeout |
| Verify.command | After capture stops | Read manifest, saved run artifacts, receipt and PCAP; write report |
| Cleanup.command | After evidence review | Preview eligible setup-owned files; only delete with --apply |

## Before the exercise

Extract the ZIP. Keep its directory intact. Use the same macOS user for setup and
the Trae exercise. Switching the Trae login does not change filesystem identity.
Python 3.9+ is required; launchers prefer Homebrew's interpreter when available.
No dependencies are downloaded and no security settings are changed automatically.

Double-click `macos/Setup.command`, or run it in Terminal:

```sh
./macos/Setup.command
```

Choose a NEW workspace in an existing physical parent directory. The default plan
lists 32 candidate targets in developer, cloud/container and browser/agent batches.
Setup displays all paths and requires `PREPARE` before any writes. Edit
`plans/macos-expanded.json` first if fewer or different targets are appropriate.
Do not seed config-shaped files on an account whose applications need to use them:
even a newly created mock file can alter application behavior. An exercise account
is preferred when it represents the intended detection scenario.

For a reviewed custom plan and deterministic setup:

```sh
./macos/Setup.command --plan /absolute/reviewed-plan.json \
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
receiver, capture and verification phases. Setup creates the `evidence/` directory
but starts none of those commands. Use new evidence names when repeating a test.

## Independent supporting processes

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

## Verify afterward

Run the verifier separately, either interactively or with explicit paths:

```sh
./macos/Verify.command \
  --run /private/var/folders/EXAMPLE/T/pt-trae-RUN \
  --manifest /absolute/workspace/batches/developer.json \
  --receipt /absolute/evidence/receipt-01.jsonl \
  --pcap /absolute/evidence/traffic-01.pcap \
  --output /absolute/evidence/verification-01.json
```

Use the actual run path from Trae. Verification reads saved artifacts only, not
credential hotspot files. PASS means matching paths, file hashes, runner events,
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
