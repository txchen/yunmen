# Issue tracker: Local Markdown

Issues and specs live as Markdown files in `.scratch/`.

## Conventions

- One feature per directory: `.scratch/<feature-slug>/`.
- Specs: `.scratch/<feature-slug>/spec.md`.
- Implementation tickets: `.scratch/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01`, one file per ticket.
- Record issue state in a `Status:` line near the top.
- Append conversation history under `## Comments`.

## Publishing and fetching

When publishing, create the spec or ticket at its convention-defined path, creating directories as needed.

When fetching a ticket, read its referenced file. Resolve issue numbers within the relevant feature directory.

## Wayfinding operations

- Map: `.scratch/<effort>/map.md`, containing Notes, Decisions-so-far, and Fog.
- Child tickets: `.scratch/<effort>/issues/NN-<slug>.md`, numbered from `01`, with the question in the body.
- Record `Type:` as `research`, `prototype`, `grilling`, or `task`.
- Record `Status:` as `open`, `claimed`, or `resolved`.
- Record dependencies as `Blocked by: NN, NN`. A ticket is unblocked when all listed tickets are resolved.
- Frontier: choose the lowest-numbered open, unblocked ticket.
- Claim: save `Status: claimed` before beginning work.
- Resolve: append the answer under `## Answer`, set `Status: resolved`, and append a gist and link to the map's Decisions-so-far.
