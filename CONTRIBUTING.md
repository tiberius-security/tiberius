# Contributing to Tiberius

Thank you for your interest in contributing to Tiberius! This document provides guidelines and information for contributors.

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or suggest features
- Search existing issues before creating a new one
- Provide clear descriptions with steps to reproduce bugs
- Include relevant logs, error messages, and environment details

### Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Ensure all tests pass: `mvn clean verify`
5. Submit a pull request

### Pull Request Guidelines

- Keep changes focused and atomic
- Write clear commit messages
- Add tests for new functionality
- Update documentation as needed
- Ensure CI checks pass

## Developer Certificate of Origin (DCO)

All contributions must be signed off using the Developer Certificate of Origin (DCO).

### What is the DCO?

The DCO is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing. The full text is available at [developercertificate.org](https://developercertificate.org/):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to Sign Off

Add a `Signed-off-by` line to your commit messages:

```
git commit -s -m "Your commit message"
```

This adds a line like:
```
Signed-off-by: Your Name <your.email@example.com>
```

Configure git to use the correct name and email:
```bash
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

## Development Setup

### Prerequisites

- Java 21+
- Maven 3.8+
- Git

### Building

```bash
# Clone the repository
git clone https://github.com/tiberius-security/tiberius.git
cd tiberius

# Build and run tests
mvn clean verify

# Run tests including Ollama integration tests (requires local Ollama)
mvn clean verify -Pollama

# Run all tests
mvn clean verify -Pall-tests
```

### Project Structure

```
tiberius/
├── src/
│   ├── main/java/io/tiberius/
│   │   ├── attack/        # Attack probe definitions
│   │   ├── core/          # Core scanning engine
│   │   ├── dataset/       # Dataset scanning
│   │   ├── fingerprint/   # Model fingerprinting
│   │   ├── fixture/       # Test fixtures
│   │   ├── guardrail/     # Guardrail testing
│   │   ├── junit/         # JUnit 5 extensions
│   │   ├── punit/         # PUnit integration
│   │   └── spring/        # Spring Boot integration
│   └── test/
│       ├── java/          # Test classes
│       └── resources/     # Test fixtures and configs
├── docs/                  # Documentation
├── pom.xml               # Maven configuration
└── README.md
```

## Code Style

- Follow standard Java conventions
- Use meaningful variable and method names
- Write Javadoc for public APIs
- Keep methods focused and concise

## Testing

- Write unit tests for new functionality
- Use descriptive test names with `@DisplayName`
- Tag integration tests appropriately (e.g., `@Tag("ollama")`)
- Ensure tests are deterministic and don't rely on external services by default

## Questions?

Feel free to open an issue for questions or discussions about contributing.

## License

By contributing to Tiberius, you agree that your contributions will be licensed under the Apache License 2.0.

## Acknowledgments

Tiberius is inspired by [Praetorian's](https://www.praetorian.com/) open source LLM security tools:
- [Augustus](https://github.com/praetorian-inc/augustus)
- [Julius](https://github.com/praetorian-inc/julius)
