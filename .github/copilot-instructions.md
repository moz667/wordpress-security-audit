# Project Guidelines

## Documentation and comments

- Write all new or updated project documentation in English, including Markdown files.
- Write all new or updated code comments and docstrings in English.
- When editing existing documentation or comments, keep the content you touch in English. Do not make unrelated bulk translations unless requested.
- Keep user-facing application text and localization files governed by the project's existing language and localization requirements; this rule applies to project documentation and code comments, not product copy.
- The user may communicate with Copilot in any language. Apply this English-language requirement to project documentation and comments regardless of the conversation language.

## Commit messages

- Use the Conventional Commits format for all commit messages: `<type>[optional scope]: <description>`.
- Write commit messages in English.
- Use a standard type that describes the change, such as `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, or `revert`.
- Mark breaking changes with `!` after the type or scope and explain them in a `BREAKING CHANGE:` footer.
- Keep the description concise and specific; do not end it with a period.

## Security analysis and file handling

- Treat YARA matches as candidates for investigation, not proof of malware.
- Analyze WordPress sites using an isolated copy or filesystem snapshot. Do not execute code from a potentially compromised site as part of analysis.
- Do not delete, sanitize, quarantine, or whitelist site files without the user's explicit approval. Base whitelist entries on verifiable evidence.
- When changing detection rules or analysis scripts, consider both false positives and missed detections, and report the validation actually performed.
- Follow the detailed project guidance in [README.md](../README.md) and [workflow-spec.md](../workflow-spec.md).
