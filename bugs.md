# Security Review Report (Bug Bounty Focus)

Date: 2026-05-08
Repository: `onlybugs05/langchain`
Scope: Targeted source review for high-impact vulnerabilities (RCE, unauthorized access, SSRF/path traversal, secrets exposure)

## Executive summary

I reviewed security-sensitive areas of the repository, with emphasis on:
- command execution surfaces,
- filesystem boundary enforcement,
- SSRF protections,
- unsafe deserialization and dangerous defaults.

### Top outcomes
1. **Potential arbitrary local file read despite `allow_dangerous_paths=False`** in prompt example loading via symlink confusion.
2. **High-risk host command execution posture** when `ShellToolMiddleware` is used with default `HostExecutionPolicy` in untrusted-input deployments.
3. **Regex-based DoS risk** in `FilesystemFileSearchMiddleware` Python grep fallback.

---

## Findings

## 1) Path restriction bypass in prompt loading (`allow_dangerous_paths=False`) via symlinked examples file

- **Severity:** High
- **Category:** Path traversal / unauthorized local file read
- **Impact:** Confidential file disclosure (e.g., credentials, API keys, environment-derived secrets) when untrusted prompt configs are accepted.

### Affected code
- `/home/runner/work/langchain/langchain/libs/core/langchain_core/prompts/loading.py:21-45` (`_validate_path`)
- `/home/runner/work/langchain/langchain/libs/core/langchain_core/prompts/loading.py:112-129` (`_load_examples`)

### Why this is vulnerable
`_validate_path` only rejects absolute paths and `..` traversal tokens. In `_load_examples`, the code then opens `Path(config["examples"])` directly and checks extension from the **symlink path name**, not the resolved target:
- validation does **not** reject relative symlinks,
- extension checks are performed on `path.suffix`, not `path.resolve().suffix`.

An attacker who can influence config and filesystem contents can provide a benign-looking relative path (e.g., `examples.yaml`) that is a symlink to a sensitive file outside the intended directory.

### Exploit sketch
1. Place/target a symlink named `examples.yaml` in working directory.
2. Point it to a sensitive file readable by the process.
3. Submit prompt config with `"examples": "examples.yaml"` and rely on default `allow_dangerous_paths=False`.
4. Loader opens and parses target content, violating path-safety expectation.

### Recommended fix
- Resolve paths before use and enforce policy on resolved target:
  - apply `resolved = path.resolve(strict=True)` in `_load_examples`,
  - validate resolved path against an explicit trusted base directory,
  - perform suffix/type checks on `resolved`, not the symlink name.
- Consider rejecting symlinks entirely for untrusted mode.

---

## 2) RCE-prone default execution posture for `ShellToolMiddleware`

- **Severity:** High (deployment-dependent)
- **Category:** Remote code execution / privilege misuse
- **Impact:** If exposed to untrusted prompts or prompt-injected tool calls, agent can execute arbitrary host commands with process privileges.

### Affected code
- `/home/runner/work/langchain/langchain/libs/langchain_v1/langchain/agents/middleware/shell_tool.py:503-566`
- `/home/runner/work/langchain/langchain/libs/langchain_v1/langchain/agents/middleware/_execution.py:92-105`

### Why this is risky
`ShellToolMiddleware` defaults to `HostExecutionPolicy` when no policy is supplied. `HostExecutionPolicy` explicitly provides no filesystem/network sandboxing and runs commands as the host process user.

This creates a high-impact RCE surface in common agent deployments where model outputs can trigger tool use (including via prompt injection from external content).

### Exploit sketch
1. App integrates agent with `ShellToolMiddleware()` default settings.
2. Untrusted user content/prompt injection coerces tool invocation.
3. Model emits shell command exfiltrating data or modifying host state.
4. Command executes directly on host environment.

### Recommended fix
- Fail closed by default for untrusted contexts:
  - require explicit policy selection instead of defaulting to host execution, or
  - default to stronger isolation policy (`DockerExecutionPolicy` / sandbox) where available.
- Add an explicit `dangerously_allow_host_execution=True` style opt-in guard with prominent runtime warning.

---

## 3) Potential ReDoS in `FilesystemFileSearchMiddleware` grep fallback

- **Severity:** Medium
- **Category:** Denial of service (CPU exhaustion)
- **Impact:** Crafted regex can trigger catastrophic backtracking when Python fallback search is used, causing prolonged CPU use and degraded service.

### Affected code
- `/home/runner/work/langchain/langchain/libs/langchain_v1/langchain/agents/middleware/file_search.py:312-353`
- `/home/runner/work/langchain/langchain/libs/langchain_v1/langchain/agents/middleware/file_search.py:202-207`

### Why this is risky
User-controlled regex is compiled and executed across file lines in Python (`regex.search(line)`), without complexity safeguards or timeout. Malicious patterns can cause expensive matching behavior.

### Recommended fix
- Prefer ripgrep-only execution with strict timeout where possible.
- For Python fallback, enforce:
  - regex complexity constraints,
  - per-match/per-file time budgets,
  - line length and total scanned-bytes ceilings,
  - optional RE2-based engine for untrusted patterns.

---

## Additional notes

- SSRF controls in `langchain_core._security._ssrf_protection` appear intentionally defensive (scheme restrictions, private/cloud metadata blocking, DNS/IP checks).
- Deserialization (`langchain_core.load.load`) clearly documents trust-boundary risks and warns defaults are unsafe for untrusted manifests; this is important and should remain highly visible in user-facing docs.

## Suggested prioritization

1. Fix finding #1 first (direct unauthorized file-read risk despite safety flag semantics).
2. Harden default posture for shell execution integrations (#2).
3. Add ReDoS controls in file-search fallback (#3).
