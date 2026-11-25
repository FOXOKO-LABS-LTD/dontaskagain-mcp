# Contributing

Thanks for your interest. Issues and pull requests are welcome.

- **Security problems**: see [SECURITY.md](SECURITY.md) — never in a public issue.
- **Bugs**: open an issue with the package version (`dontaskagain-mcp --version`), Node version, OS and MCP client.
  Never paste an agent token (`aw_…`), a pairing code or the contents of `~/.dontaskagain`.
- **Pull requests**: keep them small, add tests, and make sure these pass:

  ```bash
  npm ci
  npm test          # builds, then runs the unit and flow tests
  ```

- The package has **no runtime dependencies** (only `node:` built-ins and `fetch`); please keep it that way.
- The wallet never signs on its own: the package only sends requests that the human signs in the extension.
- By contributing you agree that your contribution is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
