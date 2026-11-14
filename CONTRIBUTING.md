# Contributing to subconverter-ng

Thank you for your interest in contributing to subconverter-ng.
Follow these guidelines to submit changes and report issues.

## Development Setup

Install Go 1.27 or newer.
Clone the repository:

```bash
git clone https://github.com/Jungley8/subconverter-ng.git
cd subconverter-ng
```

Download module dependencies:

```bash
go mod download
```

## Running Tests

Run the test suite with the race detector:

```bash
go test -race ./...
```

Run code formatting checks:

```bash
gofmt -w .
go vet ./...
```

Run the linter:

```bash
golangci-lint run ./...
```

All pull requests must pass tests, linters, and coverage checks before merge.

## Client Conformance Tests

Unit tests check the config shape we intend to emit. They cannot tell whether
the client accepts it. Some clients reject a config that looks correct to us,
such as a field moved to the wrong level or a removed option.

The conformance suite renders the fixtures in `internal/conformance/testdata`
and validates the output with the real clients. It needs one sing-box client
per schema generation: 1.11 for the pre-1.12 cases, and the current release for
the rest. sing-box 1.14 and later reject the old DNS format by design.

Install `mihomo` and both sing-box releases. Point `CONFORMANCE_SINGBOX` at both
sing-box binaries, then run:

```bash
CONFORMANCE_SINGBOX=/opt/sing-box-1.11.15,/opt/sing-box-1.14.4 make conformance
```

`CONFORMANCE_SINGBOX` is comma-separated: one path per release line. Set
`CONFORMANCE_MIHOMO` to use a specific mihomo binary instead of `PATH`. `make
conformance` sets `CONFORMANCE_REQUIRE=1`, so a missing release line fails
instead of skipping.

Add a case to `internal/conformance/conformance_test.go` when you add a target
or change the output for a client version.

When a new sing-box release becomes current:

1. Bump `defaultSingboxVersion` in `internal/generator/singbox.go`.
2. Move the cases without a declared version to the new release. Move declared
   cases to a client that still accepts their schema.
3. Bump `SB_NEW` in `.github/workflows/ci.yml`.
4. Update the current release named in `docs/url-params.md` and
   `docs/url-params.en.md`.

The nightly installs the newest release. If no case uses it, the nightly fails.

## Submitting Pull Requests

1. Create a feature branch from `main`.
2. Keep your changes focused and concise.
3. Write unit tests for new functionality.
4. Verify all tests pass locally.
5. Push your branch and open a pull request against `main`.
6. Provide a clear description of the change in the pull request template.

## Commit Guidelines

- Use clear and descriptive commit messages.
- Prefer conventional commit prefixes such as `feat:`, `fix:`, `docs:`, and `test:`.
- Sign off or configure valid author identity.

## License

By contributing, you agree that your contributions are licensed under GPL-3.0-or-later.
