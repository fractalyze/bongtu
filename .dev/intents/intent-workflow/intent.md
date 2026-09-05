# Adopt the intent chain (AI-native SDLC) for bongtu

Author: leebduk. Status: accepted.
Origin: conversation

Bootstrap note: this intent predates the chain it introduces, so its acceptance record is the
merge of the PR that ships the chain itself, intent and implementation in one.

## Problem
Feature work on bongtu starts from ad-hoc conversation: what to build, why, and the design
live only in session transcripts and PR bodies. There is no committed record of the decision
that started a piece of work, and no independent verify/review stage — the session that
writes the code also grades it.

## Proposed outcome
Every feature-scale work item leaves a committed artifact chain
(`.dev/intents/<slug>/intent.md → spec.md → plan.md`) whose lifecycle is recorded by git
events (PR merge = accepted, close = rejected), with independent sub-agents for spec
drafting, gate verification, review, and live-surface maintenance, driven by six repo-local
stage commands (`/intent /spec /plan /verify /review /maintain`).

## Affected users and systems
The development loop only: `.claude/agents/`, `.claude/skills/`, `.dev/intents/`,
`.dev/review.md`, CLAUDE.md. No runtime component changes.

## Constraints
Solo-maintainer repo: gates must stay cheap (self-merge PRs, verbal plan approval). One
owner per fact: the rubric routes to owning docs, never copies rules. Existing conventions
(workflow:commit, workflow:create-pr, public plain issues) stay authoritative.

## Open questions
Whether /maintain graduates to a schedule once its check list stabilizes.
