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
