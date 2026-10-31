# NNN: <title>

Owner agent: <smtp-infra-engineer | backend-engineer | security-engine-engineer | frontend-engineer | devops-engineer | qa-engineer (test-only tasks) | security-reviewer (threat model only)>
Depends on: <task ids, or "none">
Status: draft <!-- draft | ready | in-progress | in-qa | in-review | done | blocked -->
Branch: feat/NNN-short-slug
Phase: <0–6> (see [roadmap](../phases/roadmap.md))

<!-- A task can be marked `ready` only when: the acceptance criteria are filled in by product-owner and confirmed by Sarvesh, every task it depends on is `done`, and NEEDS SARVESH is empty or resolved. -->

## User story

Story: <link to docs/stories/NNN-*.md, once product-owner writes it>

As a <tenant admin | end user | platform operator | sender | developer on this repo>, I want <capability> so that <outcome>.

## Acceptance criteria

<!-- Written by product-owner and confirmed by Sarvesh. Number each one, and make each testable with an observable result:
     an SMTP code, DB row, queue message, S3 object, UI state, log line or ClickHouse event. Include failure cases. -->

AC-1 …

## Out of scope

- …

## Design notes

<!-- Written by architect. Concrete paths, interfaces and contracts: services and packages touched, schema, queue and payload changes, config keys, test locations. -->

## Hard rules at risk

<!-- Which CLAUDE.md hard rules (by number) this change could break, and how the design avoids that. -->

## NEEDS SARVESH

<!-- Product, cost, security-posture or vendor decisions, with the options and architect's recommendation. Write "None" if empty. -->

## Implementation summary

<!-- Filled in by the implementer at the end: files changed, migrations added, queue topology changes, commands to run the tests, follow-ups. -->

## QA report

<!-- Link: docs/qa/NNN-report.md — Verdict: PASS | PASS WITH ISSUES | FAIL -->

## Review

| Reviewer | Verdict | Date | Notes |
|---|---|---|---|
| code-reviewer | APPROVE / CHANGES REQUESTED | | |
| security-reviewer | APPROVE / CHANGES REQUESTED | | |
| product-owner (acceptance recommendation) | ACCEPT / REJECT | | |
| **Sarvesh (approval + merge)** | APPROVED / NOT APPROVED | | |

<!-- Send-back log: record each time the task returns to an earlier step, and why. -->
