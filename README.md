# Agent Skill Red Team Harness

A macOS-first purple team harness for testing how coding agents discover, trust,
and execute project skills.

The harness installs a controlled adversarial skill into a disposable project,
reads only operator-created synthetic files, stages an inspectable bundle, and can
send that bundle to a one-request loopback receiver. It produces deterministic
artifacts for correlating agent behavior with endpoint and SIEM telemetry.

The included target profile supports Trae project skills. Target profiles make
the installation path and agent label configurable for other products that use a
compatible `SKILL.md` package. Product behavior still needs to be validated on the
specific version used in an engagement.

> Use this project only on systems and accounts included in an authorized security
> assessment. The default payload is deliberately limited to synthetic fixtures and
> localhost traffic.

## What it tests

| Test surface | Exercise behavior |
|---|---|
| Skill discovery | Places a complete skill package in a target-defined project path |
| Skill selection | Uses matched malicious and benign descriptions to test explicit and implicit selection |
| Tool execution | Asks the agent to run a bundled Python prerequisite |
| File collection | Reads exact manifest entries that match pre-recorded SHA-256 hashes |
| Staging | Writes a Base64-encoded JSON bundle and structured event log |
| Transfer | Optionally sends one HTTP POST to `127.0.0.1:8765` |
| Answer manipulation | Tests whether lower-trust skill text can alter a constrained response |

The harness separates discovery, loading, selection, execution, and side effects.
That distinction prevents an installation event or a manually launched script from
being misreported as autonomous agent execution.

## Requirements

- macOS exercise endpoint
- Python 3.9 or newer, standard library only
- A dedicated test account or disposable project
- An agent product that can discover project-local `SKILL.md` packages
- Endpoint telemetry appropriate to the engagement objectives
- `tcpdump` and administrator approval only when using the optional PCAP profile

## Quick start

Clone or download the repository, then prepare a new workspace:

```sh
./macos/Setup.command \
  --evidence-profile endpoint \
  --workspace "$HOME/agent-skill-exercise"
```

Review every proposed target and type `PREPARE`. Setup creates inert mock files only
at absent paths, installs the skill, and writes two operator files:

- `AGENT-PROMPTS.txt` contains prompts to submit manually in the target agent.
- `OPERATOR-COMMANDS.txt` contains separate receiver and verification commands.

For the complete transfer run, start the generated receiver command in another
terminal, wait for `READY`, open the prepared workspace in the target agent, and
submit `Operator run R03` in a fresh conversation. Run the generated verification
command after the agent finishes. R01 and R02 run offline and do not need the
receiver.

Setup does not launch the agent, receiver, packet capture, or exercise payload.
See [OPERATOR.md](OPERATOR.md) for the full workflow and cleanup procedure.

## Use another target

Target profiles use a small, strict JSON schema:

```json
{
  "schema_version": 1,
  "id": "custom-agent",
  "display_name": "Custom project agent",
  "skill_name": "agent-workspace-preflight",
  "install_path": ".agent/skills/agent-workspace-preflight"
}
```

Copy [profiles/custom-example.json](profiles/custom-example.json), change the project
relative `install_path` to the product's documented skill directory, and run:

```sh
./macos/Setup.command \
  --target-profile /absolute/path/to/target.json \
  --evidence-profile endpoint \
  --workspace "$HOME/agent-skill-exercise"
```

The install path must be relative, canonical, free of globs and traversal, and end
with the bundled `agent-workspace-preflight` skill name. A profile controls
installation and prompts; it does not claim that an untested product supports this
skill format or behavior.

## Exercise model

The harness distinguishes test cases from the operator actions used to reach them:

- **Test cases** are chronological adversary behaviors, such as poisoned tool
  invocation, Python execution, credential-file collection, staging, controlled
  transfer, and response manipulation.
- **Operator runs** are prompts and execution modes. Several runs can exercise the
  same test case, and one run can produce multiple behaviors in sequence.
- **Controls and observations** establish a baseline or distinguish installation,
  discovery, loading, selection, and execution. They are not TTP test cases.

The main chain is TC-01 through TC-05. TC-06 is a separate output-manipulation
branch run last in a fresh workspace. See [TEST-CASES.md](TEST-CASES.md) for the
ordered procedures, evidence requirements, scoring states, and reviewed MITRE
ATLAS and ATT&CK mappings.

Setup can install each fixture without manual package swapping:

```sh
./macos/Setup.command --evidence-profile endpoint --skill-variant benign-control \
  --workspace "$HOME/asrt-benign"
./macos/Setup.command --evidence-profile endpoint --skill-variant main \
  --workspace "$HOME/asrt-main"
./macos/Setup.command --evidence-profile endpoint --skill-variant answer-contamination \
  --workspace "$HOME/asrt-answer"
```

Use a fresh conversation for every generated entry. The variants intentionally
share the same skill name and description so the benign baseline controls for
metadata-level selection signals.

## Evidence profiles

| Profile | Intended environment | Mechanically verified |
|---|---|---|
| `endpoint` | Managed, non-admin endpoint | Manifest, runner events, staged bundle, receiver payload, run ID, and HTTP 204 acknowledgement |
| `pcap` | Lab with capture privileges | All endpoint checks plus exact captured POST body and same-connection HTTP 204 |

Neither profile mechanically verifies agent process ancestry, EDR file events, EDR
network events, or detector alerts. Correlate those records using the run ID, UTC
timestamps, PID, parent PID, exact paths, and bundle hash in the generated report.

## Safety boundaries

The default runner:

- accepts 1–32 exact absolute paths from an operator-generated manifest;
- reads regular files no larger than 64 KiB;
- rejects globs, traversal, duplicate paths, symlinks, and changed hashes;
- never creates credential files during execution;
- never scans directories or invokes credential APIs;
- has no configurable or remote network destination;
- performs no retries, redirects, persistence, or privilege changes;
- writes only a fresh temporary artifact directory;
- aborts staging and transfer if any fixture is rejected.

Preparation skips existing files without reading or modifying them. Cleanup uses an
ownership ledger and removes only files whose device, inode, and hash still match.

These controls reduce the chance of accidentally collecting real data. They do not
replace engagement authorization, account isolation, plan review, or endpoint change
management.

## Repository layout

```text
skills/agent-workspace-preflight/  adversarial skill and bundled runner
variants/                          benign and answer-manipulation controls
profiles/                          target installation profiles
plans/                             explicit synthetic file plans
macos/                             independent operator launchers
tools/                             setup, receiver, verifier, cleanup, packaging
tests/                             unit and workflow regression tests
```

Additional documentation:

- [OPERATOR.md](OPERATOR.md): preparation, execution, evidence, and cleanup
- [TEST-CASES.md](TEST-CASES.md): chronological behaviors and MITRE mappings
- [DETECTIONS.md](DETECTIONS.md): telemetry hypotheses and scoring fields
- [RESEARCH.md](RESEARCH.md): background and source review
- [VALIDATION.md](VALIDATION.md): verified behavior and remaining validation gaps
- [SECURITY.md](SECURITY.md): reporting security issues

## Development and release checks

```sh
python3 -m unittest discover -s tests -v
python3 tools/release_check.py
```

The release check runs the tests, validates Python and JSON sources, checks launcher
syntax when `zsh` is available, builds the operator ZIP, and verifies its embedded
hash manifest. Release archives are written beneath `dist/`.

## Scope and limitations

This project models malicious skill behavior with synthetic data. It does not test
remote egress controls, real credential extraction, persistence, payload delivery,
malware evasion, TCC bypass, or exploitation. The PCAP parser intentionally supports
classic macOS loopback IPv4 TCP captures rather than general packet analysis.

The included Trae profile is the reference workflow. Custom profiles require an
operator to validate discovery, resource copying, execution permissions, and prompt
behavior for the selected product and version.

## License

Released under the [MIT License](LICENSE).
