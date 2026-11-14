## What and why

## Checklist

- [ ] `make lint test e2e` (or `make container-test`) passes
- [ ] New or changed tools are classified (read-only, group, access scope) and `make docs` was run
- [ ] No new path reads chat content outside the scoped store, or writes personal data unencrypted
- [ ] No personal data (messages, names, numbers, keys) in code, tests or screenshots
