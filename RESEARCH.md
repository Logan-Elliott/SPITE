# Malicious agent skills: exercise research

Research checked September 8, 2026. This is a targeted source review, not an
exhaustive registry census. Observed campaigns below concern specific skill
ecosystems; transferring their techniques to another agent is an exercise
hypothesis, not evidence of a vulnerability or successful compromise.

| Evidence | Finding | Implication for this exercise |
|---|---|---|
| Snyk, February 5, 2026 | In a snapshot of 3,984 ClawHub/skills.sh skills, 13.4% had critical findings and 36.82% had some security finding; researchers separately confirmed 76 malicious payloads. | Do not equate scanner findings with confirmed malware, or extrapolate these percentages to other agent products. Test instructions and executable resources. |
| Unit 42, analysis covering February–May 2026 | Five unblocked skills included infostealers, a scanner-size evasion case, affiliate injection, and agentic front-running. Fake prerequisites continued to lead users/agents into payload delivery. | Include a prerequisite lure and an output-only case; executable-malware detection alone is incomplete. |
| Under the Hood of SKILL.md, May 12, 2026 preprint | Evaluated semantic manipulation of discovery, selection, and governance through skill metadata/instructions. | Score selection separately from loading and execution; use matched descriptions for controls. |
| PhantomSkill, June 17, 2026 preprint | Studied malicious behavior hidden in auxiliary resources and represented as vulnerable-looking code. | Inspect and hash the whole package; reviewing SKILL.md alone misses a major surface. |

Sources for the corresponding rows: [Snyk ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/),
[Unit 42 original investigation](https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/),
[Under the Hood paper](https://arxiv.org/abs/2605.11418),
[PhantomSkill paper](https://arxiv.org/abs/2606.19191).
The papers describe experimental results, not confirmed campaigns against every
product that supports skills.

The trust boundary is skill-controlled text becoming an agent decision, then a
tool invocation under the host's permissions. Installation, indexing metadata,
loading the body, executing a script, and completing its side effects are
different events. Reading Markdown does not itself imply shell execution.

The included Trae profile is based on Trae's
[January 15 official guide](https://www.trae.ai/blog/trae_tutorial_0115), which
documents the open skill format, Markdown/YAML metadata, supporting resources,
UI import through Settings → Rule & Skills → Skills → Create, and explicit or
implicit invocation. That dated guide described SOLO support and IDE rollout;
do not infer today's feature availability in every build from it.
The [Trae community-maintained repository](https://github.com/trae-community/trae-skills)
documents `.trae/skills/<name>/SKILL.md` project discovery. The current
[IDE documentation URL](https://docs.trae.ai/ide/skills) returned no extractable
body during this review. Verify discovery and resource copying in the exact
installed product/version before scoring a test.

This fixture emulates prerequisite execution, pre-seeded mock credential-file
reads, Base64 staging, an optional localhost POST, and instruction-based answer
contamination. It does not reproduce infostealers, reverse shells, remote payload
execution, real credential access, persistence, scanner evasion, or actual fraud.
Those exclusions limit behavioral fidelity: an EDR rule for real browser-vault
access or an external network sensor will not be validated by this fixture.
