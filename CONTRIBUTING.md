# Contributing

Thanks for helping! `mcp-wpp` exposes some of the most private data people have, so changes are reviewed first for their security impact. Read the **Security invariants** in [AGENTS.md](AGENTS.md) before you start.

## Scope

- **Here:** the MCP server, consent policy, encryption, cache, daemon, CLI and packaging.
- **Upstream:** WhatsApp protocol, sessions and media transfer belong to [whatsmeow](https://github.com/tulir/whatsmeow).

## Before you start

- Open an issue before substantial work so the scope can be agreed.
- Keep each pull request focused on one change, with tests.
- Never commit keys, tokens, databases, `data/`, `secrets/`, media, or real phone numbers and chat names. CI runs a secrets scan.

## Build and test

You need Go 1.26+, a C toolchain and SQLCipher (`dnf install sqlcipher-devel`, `apt install libsqlcipher-dev`, `brew install sqlcipher`), or just Docker/Podman.

```bash
make hooks                 # once: checks commit messages, runs lint+test before push
make check                 # every CI gate, natively (needs golangci-lint and govulncheck)
make container-test        # the test stage in Debian, nothing to install
make docs                  # after adding or changing a tool
```

Tests use fixtures and throwaway encrypted stores; they never need a WhatsApp account. For manual testing, pair a spare number with `wpp-mcp pair -phone +<number>`.

## Pull requests

- Target `main`. Commit subjects and PR titles must be `type(scope): summary` ([Conventional Commits](https://www.conventionalcommits.org/) with a mandatory scope), for example `fix(store): keep access decisions on retention`. Mark breaking changes with `!` and a `BREAKING CHANGE:` footer. PRs are squash-merged with their title.
- Describe the user-facing change and why.
- If you touch a tool, update its three classifications (read-only, group, access scope) and regenerate `docs/tools.md`.

## Windows

Building needs CGO and a C compiler (see [docs/windows.md](docs/windows.md)). Encryption needs SQLCipher, which is easiest to get through Docker or WSL.
