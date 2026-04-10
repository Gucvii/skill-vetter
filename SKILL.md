---
name: skill-vetter
version: 1.2.0
user-invocable: true
description: "Multi-scanner security gate with AI-guided sandbox recommendations. TRIGGER when: user mentions installing, adding, or reviewing a skill to Claude Code, OpenClaw, or any other AI agent. Detects malicious code, contract violations, tampering, and suspicious patterns."
permissions: [exec, network, write]
---

# Skill Vetter

Security gate that runs multiple scanners against a skill before installation, then provides an **AI-guided recommendation** on whether to proceed, review, or run an optional sandbox test.

## When to Use

Use before installing **ANY** skill to Claude Code, OpenClaw, or your other favorite AI agent — whether from ClawHub, GitHub, or any external source.

Ask the user: "Should I run skill-vetter on this before installing?" whenever they mention installing a new skill.

## How to Run

### Check dependencies first

```bash
bash {baseDir}/scripts/check-deps.sh
```

Fix any missing dependencies before proceeding.

### Run the full scan

```bash
bash {baseDir}/scripts/vett.sh "<skill-name-or-path>"
```

The argument can be:
- A ClawHub skill name: `youtube-summarize`
- A GitHub URL: `https://github.com/user/repo`
- A local path: `/tmp/my-skill/`

The scan output ends with a `META:` JSON line. You must parse it to generate the AI recommendation.

## Interpret Results

| Verdict | Meaning | Action |
|---------|---------|--------|
| **BLOCKED** | CRITICAL or HIGH findings | Do NOT install unless user explicitly overrides. |
| **REVIEW NEEDED** | Medium severity findings | Show findings, explain, and ask user to decide. |
| **SAFE** | All scanners passed | Still evaluate sandbox recommendation before auto-installing. |

## After Verdict — AI Recommendation Workflow

After `vett.sh` completes, do **not** stop. Follow this exact workflow:

### 1. Parse the META line

Extract the JSON after `META:`. Example:

```json
{"sandbox_recommended":"strongly","sandbox_reason":"Static findings present + executable code","has_executable":true,"failures":1,"warnings":0}
```

Fields:
- `sandbox_recommended`: `strongly` | `recommended` | `skip`
- `sandbox_reason`: human-readable rationale
- `has_executable`: `true` if the skill contains scripts or compiled code
- `failures` / `warnings`: numeric counts from static scan
- `sandbox_run`: `true` if sandbox was executed
- `sandbox_violations`: `true` if sandbox detected violations
- `llm_judge_run`: `true` if the LLM judge scanner was executed
- `llm_judge_score`: risk score string from LLM judge (e.g., `"6"`) or `""` if skipped

### 2. Read the skill description

Open `$SKILL_DIR/SKILL.md` and read its `description` field (or first paragraph). Understand what the skill claims to do and what tools it says it needs.

### 3. Generate the AI recommendation

Use the static scan results, the META line, and the skill description to choose one of the following recommendation levels:

| Level | Trigger Conditions | Default Action |
|-------|-------------------|----------------|
| **🔴 强烈建议 sandbox** | `failures > 0` or `warnings > 0` **and** `has_executable == true`; or workspace tampering detected | Pre-select "运行 sandbox" |
<!-- aguara-ignore-next-line SUPPLY_018 -->
| **🟡 建议 sandbox** | `failures == 0` and `warnings == 0` **but** `has_executable == true`; or skill description implies network/exec behavior without executable files | Pre-select "运行 sandbox" but allow skip |
| **🟢 可不 sandbox** | `failures == 0`, `warnings == 0`, no executable code, but skill processes data or generates code | Pre-select "直接安装" but offer sandbox as an option |
| **⚪ 跳过 sandbox** | Pure Markdown prompt / command definition, no executable entry, all green | Direct install (still ask user to confirm) |

### 4. Present the recommendation to the user

Your message should include:
1. The static scan verdict and summary (pass/fail per scanner)
2. The **AI 建议** with a one-sentence "为什么"
3. A clear next-step question

**Example messages:**

> 🔴 **AI 建议：强烈建议追加 sandbox 验证**
> 
> 原因：静态扫描发现 1 项高危 + 1 项中风险，且该 skill 包含可执行的 shell 脚本。虽然代码本身可能只是正常功能，但运行时行为（网络请求、文件写入）无法通过静态分析完全确认。
> 
> 是否先运行 sandbox 动态验证？（推荐）

> 🟡 **AI 建议：建议追加 sandbox 验证**
> 
> 原因：静态扫描 5/5 全通过，但 skill 包含 Python 脚本，并声明了网络访问能力。为保障安全，建议在隔离环境中跑一遍确认无副作用。
> 
> 是否运行 sandbox 验证？（推荐）

> ⚪ **AI 建议：可直接安装**
> 
> 原因：这是一个纯 Markdown 的文本格式化命令，没有任何可执行代码，静态扫描也完全通过。
> 
> 确认安装吗？

### 5. If the user agrees to sandbox

Run:

```bash
bash {baseDir}/scripts/vett.sh "<skill-name-or-path>" --sandbox
```

Then show the combined static + sandbox report and ask for final approval.

### 6. Never install automatically

**Always** wait for explicit user confirmation after showing findings and the AI recommendation.

## Scanners Used

| Scanner | What It Checks |
|---------|---------------|
| aguara | Prompt injection, obfuscation, suspicious LLM calls |
| skill-analyzer | Known malicious patterns, CVE database |
| secrets-scan | Hardcoded API keys, tokens, credentials |
| structure-check | Missing SKILL.md, malformed YAML, dangerous shell commands |
| contract-check | Capability contract violations, workspace tampering, undeclared permissions |
| llm-judge | LLM-as-a-Judge semantic scan for prompt injection, social engineering, and deceptive behavior |

## Example Output

```
════════════════════════════════════════════════════════════
SKILL VETTER — Security Scan: malicious-skill
Path: /tmp/skill-vetter-abc123/malicious-skill
════════════════════════════════════════════════════════════

[1/6] aguara............. ✅ PASS
[2/6] skill-analyzer..... ❌ FAIL (HIGH: prompt injection pattern)
[3/6] secrets-scan....... ⚠️  WARN (Medium: base64 encoded string)
[4/6] structure-check.... ✅ PASS
[5/6] contract-check..... ❌ FAIL (workspace tampering detected)
[6/6] llm-judge.......... ⚠️  WARN (risk 6 — prompt injection pattern detected)

════════════════════════════════════════════════════════════
VERDICT: 🚫 BLOCKED
Reasons: 2 HIGH/CRITICAL, 1 MEDIUM
════════════════════════════════════════════════════════════

Do NOT install this skill. Issues found:
- HIGH: Prompt injection in SKILL.md (line 47)
- MEDIUM: Base64 encoded string in scripts/run.sh (line 12)
- FAIL: Workspace config tampering detected

META: {"sandbox_recommended":"strongly","sandbox_reason":"Static findings present + executable code","has_executable":true,"failures":2,"warnings":1,"sandbox_run":false,"sandbox_violations":0,"llm_judge_run":true,"llm_judge_score":"6"}
```

## Dependencies

- `aguara` — Go-based prompt scanner
- `skill-analyzer` — Cisco AI skill scanner (Python)
- `greywall` *(optional)* — Kernel-enforced sandbox for runtime verification
- `python3` — For additional checks
- `curl`, `jq` — For API calls and JSON parsing

Run `check-deps.sh` to verify all tools are installed.
