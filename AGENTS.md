## Language

Conversations with the user may be in Chinese. All content written to the repository must be in English, including code comments, documentation, and tests.

## Testing

Keep testing proportional to the change and fast enough to support rapid iteration. Focus on common behavior and meaningful failure risks; avoid extensive coverage of extremely rare corner cases.

Keep UI unit tests selective: add them when the component is easy to test and the tests run quickly. Keep end-to-end tests focused and fast. Test scope and runtime should support iteration speed.

## Agent skills

### Issue tracker

Issues and specs live in `.scratch/<feature>/`. Before creating, reading, or updating tickets, read `docs/agents/issue-tracker.md`.

### Domain docs

Single-context layout. Before exploring the codebase, read `docs/agents/domain.md`.
