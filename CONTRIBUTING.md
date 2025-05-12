# Contributing to MiniOAuth2

First off, thank you for considering contributing to MiniOAuth2! We appreciate your time and effort.

This document provides guidelines for contributing to the project.

## How Can I Contribute?

### Reporting Bugs

*   Ensure the bug was not already reported by searching on GitHub under [Issues](https://github.com/Mhr1375/MiniOAuth2/issues). <!-- Replace with actual repo URL if needed -->
*   If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/Mhr1375/MiniOAuth2/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements

*   Open an issue and provide a clear description of the suggested enhancement and its potential benefits.
*   Explain why this enhancement would be useful to most MiniOAuth2 users.
*   Provide code examples if possible to illustrate the use case.

### Pull Requests

*   Fork the repository and create your branch from `master`.
*   If you've added code that should be tested, add tests.
*   Ensure the test suite passes (`ctest` in the build directory).
*   Make sure your code lints (if a linter is set up).
*   Issue that pull request!

## Areas for Contribution

We are actively looking for contributions in the following areas:

*   **More Unit Tests:** Expanding test coverage for existing and new functionality is always welcome. Especially for edge cases in parsing, encoding, and PKCE generation.
*   **Additional OAuth Providers:** Adding predefined configurations (`minioauth2::config::ProviderName()`) for other popular OAuth 2.0 providers (e.g., GitHub, Microsoft, Facebook).
*   **Token Refresh Flow:** Implementing helper functions for the token refresh grant type.
*   **JWT Validation:** While full JWT validation is complex, adding basic claim validation (e.g., `exp`, `aud`, `iss`) could be a valuable optional feature (perhaps requiring another dependency).
*   **Improved Error Handling:** Making error messages more specific and potentially introducing custom exception types.
*   **Example Enhancements:** Improving the existing example or adding new ones (e.g., showing refresh token usage, using a different web framework).
*   **Documentation:** Improving comments in the code or enhancing the README.

## Styleguides

*   Try to follow the existing code style (consistent indentation, naming conventions, etc.).
*   Use comments where necessary to explain complex logic.

## Questions?

Feel free to open an issue if you have questions about contributing or the project in general.

We look forward to your contributions! 