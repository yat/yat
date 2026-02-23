# AGENTS.md

Guidance for future runs in this repo.

## Primary preference

Readability and maintainability are first-order goals.
Small, obvious code is preferred over speculative robustness.
Do not toy with these people.

## Minimal-change mandate

When implementing a requested feature or fix, change the fewest lines needed for correct behavior.

- Do not refactor nearby code unless it is required to make the requested change correct.
- Do not rename, reorder, move, or reformat unrelated code in the same edit.
- Preserve existing control-flow shape unless changing it is necessary for the requested behavior.
- If two approaches are both correct, prefer the one with the smaller, easier-to-review diff.

Avoid low-value ceremonial defensive code.
- Do not add guards for states that cannot occur under current invariants.
- Do not add "future-proof" branches unless requested.
- Do not add checks just because they are cheap.

If you think a defensive check is necessary, tie it to one of:
- a real external input boundary
- an explicit protocol constraint
- a known failure mode in current code paths

## Required first step on every edit

Before writing code, inspect both diff layers:

1. `git diff --cached`
2. `git diff`

Reason: this repo often has staged and unstaged work at the same time. If you only read one layer, you will misread intent and style. This is important but you don't need to announce it every time.

## Style and change expectations

1. Prefer the smallest mechanism that solves the request.
- If an atomic counter is sufficient, do not introduce a semaphore.
- If logic is single-use and clear inline, do not extract a helper.

2. Optimize for clarity over ceremony.
- Prefer straightforward control flow over layered abstractions.
- Remove complexity that does not buy immediate correctness or required behavior.
- Keep diffs scan-friendly and obvious.

3. Keep logging exact and minimal.
- Message text is part of the contract.
- Only include requested fields.
- Do not add explanatory fields like `reason` unless explicitly requested.

4. Match file-local style, not generic best practices.
- Follow existing control-flow shape and naming in the target file.
- Avoid adding "architectural" layers for small behavior changes.
- Keep comments sparse and useful.

5. Avoid hidden behavior changes.
- Do not silently shift semantics while "cleaning up".
- Keep changes narrowly scoped to the requested behavior.

6. Optimize for maintainer review speed.
- A maintainer should understand the diff at a glance.
- If a helper/abstraction adds cognitive load, remove it.

## Change-shape discipline

When a maintainer requests a structural change, preserve everything not explicitly in scope.

- Change only the requested dimension. If the ask is "remove nesting", do not also swap control-flow style, naming style, or error-shape conventions.
- Do not make speculative style or micro-optimization substitutions. If a change is not required for correctness or explicitly requested, leave it alone.
- For hot-path "cleanups", prioritize reviewer intent over personal preference: equivalent behavior with smaller, clearer diffs.
- If a potential improvement is optional, present it separately after completing the requested change.

## API goroutine ownership

- Default: do not start goroutines inside API methods.
- Prefer blocking APIs where the caller chooses whether to call directly or launch a goroutine.
- Only start internal goroutines when the API contract explicitly requires internal background lifecycle management.

## Defensive-code policy

- Default stance: do not add defensive checks unless they are needed now.
- Keep invariant assumptions local and obvious in code shape.
- Prefer deleting redundant checks over preserving them "just in case."
- If a guard stays, it should protect a realistic boundary (network input, parsing, file IO, user input, or explicit protocol max/min).

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

5. Calibrate API breakage concerns to current usage.
- This package currently has no external consumers.
- Unless explicitly requested, evaluate API compatibility impact within this repo only.

## Test style

- Use `for b.Loop()` in benchmarks instead of `for i := 0; i < b.N; i++`.
- Hard rule: generated tests must be in files named `ai_*_test.go`.
- Prefer external `_test` packages (for example `servertls_test`) when writing tests.
- Use same-package tests only when access to internals is absolutely required.
- If internals are required, prefer separating them into a dedicated `*_internal_test.go` file.
- Prefer behavior/state assertions over message-text assertions so tests remain stable when diagnostics evolve. Do not assert logger output in generated tests.

## Pre-submit checklist

- [ ] I reviewed `git diff --cached` and `git diff` first.
- [ ] Every changed line is directly tied to the request.
- [ ] I avoided unnecessary helpers/abstractions/defensive ceremony.
- [ ] Log messages/fields exactly match user direction.
- [ ] The diff is easy to scan and hard to misinterpret.
