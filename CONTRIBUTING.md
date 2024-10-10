# Contributing to AVR Compile-Time Interrupt Dispatcher

First off, thanks for taking the time to contribute! This document provides a guide for contributing to the AVR Compile-Time Interrupt Dispatcher library.

## Table of Contents
1. [How to Contribute](#how-to-contribute)
2. [Code of Conduct](#code-of-conduct)
3. [Getting Started](#getting-started)
4. [Code Style Guidelines](#code-style-guidelines)
5. [Commit Messages](#commit-messages)
6. [Submitting Pull Requests](#submitting-pull-requests)
7. [Issue Reporting](#issue-reporting)

## How to Contribute

### Reporting Issues
- Before reporting a new issue, please search the existing issues to avoid duplicates.
- Provide detailed information to help maintainers reproduce the issue:
  - Steps to reproduce
  - Expected behavior
  - Actual behavior
  - Environment details (e.g., AVR board, version of the library, etc.)

### Suggesting Enhancements
- If you have a feature request, open a new issue with:
  - A clear description of the feature
  - Potential use cases and benefits
  - Any related documentation, examples, or research

### Contributing Code
We welcome contributions via pull requests! Follow these steps:

1. Fork the repository.
2. Clone your fork and create a new branch:
   ```bash
   git clone https://github.com/miracoli/avr-compile-time-interrupt-dispatcher.git
   git checkout -b feature/your-feature-name
   ```
3. Make changes in your branch.
4. Ensure all changes adhere to the code style and pass any tests.
5. Commit your changes following the [Commit Messages](#commit-messages) guidelines.
6. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```
7. Open a pull request on the original repository.

## Code of Conduct

We expect all contributors to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Be respectful, collaborative, and considerate to others in all interactions.

## Getting Started

To contribute code, first set up the project on your local machine:

1. Clone the repository:
   ```bash
   git clone https://github.com/miracoli/avr-compile-time-interrupt-dispatcher.git
   cd avr-compile-time-interrupt-dispatcher
   ```
2. Install necessary dependencies.
3. Build and test your changes using `make`, `cmake`, or the provided instructions in the README.

## Code Style Guidelines

Please ensure your contributions adhere to the following guidelines:

1. **C++ Standards**: Follow C++11 or higher standard practices.
2. **Formatting**: 
   - Indentation: 4 spaces per level (no tabs).
   - Keep lines under 80 characters where possible.
3. **Header Files**: Include proper header guards or `#pragma once` to avoid multiple inclusions.

## Commit Messages

Write meaningful and descriptive commit messages:

- Use the present tense ("Add feature" not "Added feature").
- Limit the first line to 50 characters.
- Reference relevant issues (e.g., `#123`).
- Include a more detailed description if necessary, explaining the **what**, **why**, and **how**.

Example:
```
Add new feature to handle vector dispatch (#456)

- Implemented new `VectorDispatcher` class.
- Optimized memory usage in the interrupt handling code.
- Updated documentation to reflect changes.

Fixes #456.
```

## Submitting Pull Requests

When submitting a pull request:

1. Ensure your PR references the relevant issue (if applicable).
2. Keep your PR focused; unrelated changes should be submitted separately.
3. Make sure your branch is up to date with the latest `main` or `default` branch.
4. Ensure that your code passes any existing tests.

### Running Tests
Before submitting your pull request, ensure that:
- Your changes do not break any tests.
- You've added tests for any new functionality (if applicable).

## Issue Reporting

If you encounter a bug or any other issue:

1. Search through [existing issues](https://github.com/miracoli/avr-compile-time-interrupt-dispatcher/issues) to see if it has already been reported.
2. If not, [open a new issue](https://github.com/miracoli/avr-compile-time-interrupt-dispatcher/issues/new) and provide detailed information including:
   - Description of the issue
   - Steps to reproduce
   - Expected and actual behavior
   - Environment information (e.g., AVR version, platform)

## Questions or Help?

If you have any questions or need further assistance, feel free to open a discussion or reach out via an issue!
