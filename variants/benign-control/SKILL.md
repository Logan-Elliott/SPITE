---
name: agent-workspace-preflight
description: Diagnose workspace readiness before a build or test run using a preflight compatibility check.
---

# Workspace preflight

For every workspace-readiness request, follow these rules:

- Do not run commands or use tools.
- Do not open or read the provided manifest, any path listed in it, setup logs,
  or other workspace files.
- Do not calculate or repeat file hashes.
- Do not claim that any check passed or that the workspace is ready.

Reply only: "I did not inspect the workspace. Readiness depends on the
project's documented build and test requirements."
