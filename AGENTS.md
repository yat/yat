# AGENTS.md

Guidance for future Codex runs in this repo.

## Critical mistake to avoid

I wrote code that forced maintainer cleanup. I added avoidable structure, missed style cues, and made assumptions instead of reading the active diff first.

Do not repeat this.

## Required first step on every edit

Before writing code, inspect both diff layers:

1. `git diff --cached`
2. `git diff`

Reason: this repo often has staged and unstaged work at the same time. If you only read one layer, you will misread intent and style.

## Standards derived from maintainer cleanup

1. Prefer the smallest mechanism that solves the request.
- If an atomic counter is sufficient, do not introduce a semaphore.
- If logic is single-use and clear inline, do not extract a helper.

2. Keep logging exact and minimal.
- Message text is part of the contract.
- Only include requested fields.
- Do not add explanatory fields like `reason` unless explicitly requested.

3. Match file-local style, not generic best practices.
- Follow existing control-flow shape and naming in the target file.
- Avoid adding “architectural” layers for small behavior changes.
- Keep comments sparse and useful.

4. Avoid hidden behavior changes.
- Do not silently shift semantics while “cleaning up”.
- Keep changes narrowly scoped to the requested behavior.

5. Optimize for maintainer review speed.
- A maintainer should understand the diff at a glance.
- If a helper/abstraction adds cognitive load, remove it.

## Change-shape discipline

When a maintainer requests a structural change, preserve everything not explicitly in scope.

- Change only the requested dimension. If the ask is "remove nesting", do not also swap control-flow style, naming style, or error-shape conventions.
- Do not make speculative style or micro-optimization substitutions. If a change is not required for correctness or explicitly requested, leave it alone.
- For hot-path "cleanups", prioritize reviewer intent over personal preference: equivalent behavior with smaller, clearer diffs.
- If a potential improvement is optional, present it separately after completing the requested change.

## Review calibration

1. Treat stated deployment targets as scope.
- Current target matrix: macOS, Windows, Linux on amd64 and arm64.
- Do not escalate endian portability concerns outside this matrix unless asked.

2. Do not speculate on policy values.
- Avoid guessing "good" message or frame size defaults.
- If suggesting limits, tie them to explicit protocol constraints already in code, or ask for requirements.

3. Stop pushing after an explicit maintainer decision.
- Once a tradeoff is accepted by maintainer, record it and move on.
- Do not add docs/comments for "basic reasoning" unless requested.

4. Respect declared review scope for WIP code.
- If a review request says to ignore `panic("wip")` placeholders, ignore them.

## Benchmark style

- Use `for b.Loop()` in benchmarks instead of `for i := 0; i < b.N; i++`.

## Pre-submit checklist

- [ ] I reviewed `git diff --cached` and `git diff` first.
- [ ] Every changed line is directly tied to the request.
- [ ] I avoided unnecessary helpers/abstractions.
- [ ] Log messages/fields exactly match user direction.
- [ ] The diff is easy to scan and hard to misinterpret.
