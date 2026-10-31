# Domain docs

## Before exploring

Read the root `GLOSSARY.md` and relevant ADRs in `docs/adr/`.

If these files do not exist, proceed silently. Domain modeling creates them lazily as terms and decisions are resolved.

## Layout

This repo uses a single-context layout:

- `GLOSSARY.md`: domain vocabulary.
- `docs/adr/`: architectural decision records.

## Vocabulary

Use glossary terms when naming domain concepts in issues, proposals, hypotheses, and tests.

If a needed concept is absent, reconsider whether it belongs to the domain or note the gap for domain modeling.

## ADR conflicts

Explicitly identify any proposal that contradicts an existing ADR and explain why the decision should be reopened.
