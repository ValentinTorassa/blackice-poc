# Specs

One spec per component of blackice. Each spec answers five questions, in this order:

1. **What and why**: what the component does and why it exists, in plain language.
2. **Requirements**: what it must do, as numbered, testable statements.
3. **Design**: how it works, with a short technical layer.
4. **Tasks**: who is building which part, and what is blocking.
5. **Evidence**: what proves each requirement. Nothing counts as working without it.

A sixth section lists the terms the spec uses; each one is defined in [glossary.md](glossary.md).

Specs describe the product. They do not hold plans, schedules or discussion.

## Files

- `docs/specs/<id>.md`: one file per component. Copy [`_template.md`](_template.md) to start one.
- `docs/specs/glossary.md`: every term a spec uses, in plain language and then technically.

## Front matter

```yaml
---
id: proxy                  # file name without .md; lowercase, dashes
title: Proxy
owner: lead                # who builds it: lead | codex | codex-linux | network | appfilter | security | marketing | spec; comma-separated if shared
stage: v0                  # v0: needed for the v0 checkpoints; release: needed later
paths: src/proxy/          # code that implements it, comma-separated; empty if none yet
cases: P0-02, P0-03        # v0 checkpoints it serves (see evidence/README.md)
depends: policy, receipts  # other specs it relies on
---
```

There is no `state` field. The state is computed (see [States](#states)).

## Sections

The headings are fixed, so a script can read them:

```markdown
## What and why
## Requirements
## Design
## Tasks
## Evidence
## Terms
```

### What and why

Three to six sentences that someone outside the project can follow. No jargon without a glossary entry.

### Requirements

```markdown
| ID | Requirement | Checks |
|---|---|---|
| proxy.R1 | When a CONNECT request names a host the policy does not allow, the proxy shall refuse it with 403 and write one receipt. | P0-02 |
```

- **ID**: `<id>.R<n>`. Never renumber. A requirement that is no longer wanted keeps its row with
  `(dropped)` at the start of the text.
- **Requirement**: one testable statement. Use "When <trigger>, blackice shall <response>." for event-driven
  behaviour, "blackice shall <response>." for something always true, and "If <unwanted condition>, blackice shall
  <response>." for failures. Say what is observable, not how it is built.
- **Checks**: the checkpoint IDs (`P0-xx`) it serves, or `-`.

### Design

Plain language first, then a **Technical** paragraph or list: interfaces, file formats, OS mechanisms,
limits. Name what the design does not cover.

### Tasks

```markdown
| Task | Owner | State | Blocked by |
|---|---|---|---|
| Parse policy v0 and reject unknown fields | lead | done | |
```

- **Owner**: `lead`, `codex`, `codex-linux`, `network`, `appfilter`, `security`, `marketing`, `spec` or `valen`.
- **State**: `todo`, `doing`, `done` or `blocked`. Use `blocked` only for something outside the normal build order: a
  decision, an account, a machine, a person. A `todo` that simply comes after other work may name that work in
  **Blocked by**.

Builders update their own rows as they work, in the same commit as the change.

### Evidence

```markdown
| Covers | Kind | Link | Note |
|---|---|---|---|
| proxy.R9 | entry | [P0-02 macOS](../../evidence/P0-02-real-deny-macos.md) | |
| proxy.R1 | test | `zig build test` (src/proxy/proxy.zig, "refuses a host outside the policy") | |
```

- **Covers**: one or more requirement IDs, comma-separated.
- **Kind**:
  - `entry`: a file in [`evidence/`](../../evidence/README.md) from a real run. Only this kind verifies a
    requirement.
  - `test`: an automated test that exercises the requirement. It shows the code does what the test checks; it
    does not show the OS enforces anything.
  - `receipt`: receipt lines from a run, kept with an entry.
  - `probe`: a feasibility experiment that does not use blackice code. Shown for context; it never counts.
- Add a row only after the run or test is real.

### Terms

A comma-separated list of glossary terms used in the spec, for example `policy, receipt, CONNECT proxy`.

## States

The state of a component is computed from its spec, the `evidence/` folder and the project's decision records.
Nobody types it. In order of precedence:

| State | Meaning |
|---|---|
| verified | Every requirement that is not dropped has an `entry` whose file exists. |
| blocked | Not verified, and at least one task is `blocked`. |
| built | Every requirement has a `test` or an `entry`. |
| decided | The approach is agreed and the requirements are written; building is not finished. |
| proposed | Anything else. |

A requirement shows `verified` (an entry exists), `tested` (a test exists), `probe only` or `open`.

A component with `stage: release` is not part of the v0 checkpoints. It shows as `pending` until it is
verified, whatever its tasks say.

## Writing rules

- English, plain words, short sentences.
- A capability is described as working only when an `entry` backs it. Otherwise write "designed" or "planned".
- State limits next to claims.
- No secrets, no private conversations, no names of people outside the project.
