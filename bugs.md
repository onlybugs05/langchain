# Security Review Report (Bug Bounty Focus)

Date: 2026-05-09  
Repository: `onlybugs05/langchain`  
Scope: Security review of filesystem-boundary and prompt-loading code paths for high-impact issues (unauthorized access, sensitive data exposure, and exploit chains that can enable account takeover).

## Executive Summary

I reviewed high-risk surfaces in the current codebase and identified two new filesystem-boundary bypasses that can violate security assumptions in “restricted path” modes:

1. `FilesystemFileSearchMiddleware.glob_search` allows root escape using crafted glob patterns and symlink dereferencing.
2. Prompt loading with `allow_dangerous_paths=False` still permits symlink-based escape for `template_path` and `example_prompt_path` (distinct from the excluded known issue involving `examples`).

Both findings can expose sensitive local files and configuration data and may lead to credential theft in real deployments.

## Findings

### 1) Root-path escape in `FilesystemFileSearchMiddleware.glob_search` via unvalidated glob pattern

- **Severity:** High  
- **Category:** Path traversal / unauthorized filesystem access  
- **Impact:** An attacker controlling tool inputs can enumerate files outside the configured `root_path`, breaking sandbox expectations and potentially discovering sensitive targets (keys/config files) for follow-on abuse.

**Affected code**
- `/home/runner/work/langchain/langchain/libs/langchain_v1/langchain/agents/middleware/file_search.py:160-166`
- `/home/runner/work/langchain/langchain/libs/langchain_v1/langchain/agents/middleware/file_search.py:235-257`

**Exploit sketch**
1. Application exposes `glob_search` to untrusted model/user input with `root_path` intended as confinement.
2. Attacker supplies `pattern="../../etc/passwd"` (or `../**/*`) with default `path="/"`.
3. `base_full.glob(pattern)` yields matches outside root.
4. Code returns escaped virtual paths like `/../../etc/passwd`, confirming access outside sandbox.

**Recommended fix**
- Validate `pattern` and reject traversal tokens and absolute-like patterns before calling `glob`.
- Resolve each candidate (`match.resolve()`) and enforce `resolved.relative_to(self.root_path)` before accepting.
- Consider hard-failing on any match that escapes root, not just dropping it silently.

---

### 2) Symlink-based path restriction bypass in prompt loading for `template_path` and `example_prompt_path` when `allow_dangerous_paths=False`

- **Severity:** High  
- **Category:** Path restriction bypass / unauthorized local file read  
- **Impact:** Attackers who can influence prompt config + local symlink placement can load prompt data from outside intended safe paths, exposing secrets stored in local text/JSON/YAML files.

**Affected code**
- `/home/runner/work/langchain/langchain/libs/core/langchain_core/prompts/loading.py:21-45` (`_validate_path`)
- `/home/runner/work/langchain/langchain/libs/core/langchain_core/prompts/loading.py:85-109` (`_load_template`)
- `/home/runner/work/langchain/langchain/libs/core/langchain_core/prompts/loading.py:157-173` (`_load_few_shot_prompt`, `example_prompt_path` flow)
- `/home/runner/work/langchain/langchain/libs/core/langchain_core/prompts/loading.py:245-265` (`_load_prompt_from_file`)

**Exploit sketch**
1. Attacker provides config with relative `template_path` or `example_prompt_path` that passes `_validate_path` (no absolute path, no `..`).
2. Path is a symlink to a file outside the trusted directory boundary.
3. Loader resolves/follows symlink and reads/parses target file.
4. Protected mode (`allow_dangerous_paths=False`) is bypassed for these fields.

**Recommended fix**
- In restricted mode, reject symlinks for all file path fields (`template_path`, `example_prompt_path`, and nested loads), or strictly enforce resolved path containment against an explicit trusted base.
- Apply path policy to resolved targets, not only the original user-supplied path string.
- Add regression tests specifically for symlink escapes on `template_path` and `example_prompt_path`.

## Suggested Prioritization

1. **P0:** Fix `glob_search` root-escape and symlink dereference behavior in `FilesystemFileSearchMiddleware` (immediately user-reachable in agent tool execution paths).
2. **P0/P1:** Close prompt-loading symlink bypasses for `template_path` and `example_prompt_path` under `allow_dangerous_paths=False`.
3. **P1:** Add cross-module path-safety invariants and shared helper coverage (resolve + containment checks + symlink policy) to prevent similar regressions.
