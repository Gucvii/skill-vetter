# Skill Vetter

Multi-scanner security gate for [OpenClaw](https://openclaw.ai) skills. Run before installing any skill from ClawHub or external sources to detect malicious code, vulnerabilities, and suspicious patterns.

## Usage

Check dependencies:

```bash
bash scripts/check-deps.sh
```

Run a scan:

```bash
bash scripts/vett.sh <skill-name | github-url | local-path>
```

## Scanners

| Scanner | What It Checks |
|---------|----------------|
| [aguara](https://github.com/garagon/aguara) | Prompt injection, obfuscation, suspicious LLM calls |
| [skill-scanner](https://pypi.org/project/cisco-ai-skill-scanner/) | Known malicious patterns, CVE database |
| secrets-scan | Hardcoded API keys, tokens, credentials |
| structure-check | Missing SKILL.md, malformed YAML, dangerous shell commands |

## Verdicts

| Verdict | Action |
|---------|--------|
| **SAFE** | All scanners passed — proceed with installation |
| **REVIEW NEEDED** | Medium severity findings — review before deciding |
| **BLOCKED** | Critical/high findings — do not install |

## Dependencies

```
aguara          go install github.com/garagon/aguara/cmd/aguara@latest
skill-scanner   pip install cisco-ai-skill-scanner
python3, curl, jq, git
```

## License

MIT
