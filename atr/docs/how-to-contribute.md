# 3.8. How to contribute

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.7.` [Code conventions](code-conventions)

**Next**: (none)

**Sections**:

* [Introduction](#introduction)
* [Finding something to work on](#finding-something-to-work-on)
* [Pull request workflow](#pull-request-workflow)
* [Commit message style](#commit-message-style)
* [ASF contribution policies](#asf-contribution-policies)
* [Special considerations for ATR](#special-considerations-for-atr)
* [Getting help](#getting-help)

## Introduction

ATR is developed by ASF Tooling in public as open source code, and we welcome high quality contributions from external contributors. Whether you are fixing a typographical error in documentation, improving an error message, implementing a new feature, or addressing a security issue, your contribution helps to improve ATR for all of our users.

This page explains how to contribute code and documentation to ATR. We recommend reading the [platform introduction](introduction-to-atr) and [overview of the code](overview-of-the-code) first to understand the purpose of ATR and how the codebase is structured. You should also read the [code conventions](code-conventions) page; we expect all contributions to follow those conventions.

## Finding something to work on

The easiest way to find something to work on is to look at our [issue tracker](https://github.com/apache/tooling-trusted-releases/issues) on GitHub. We label [issues that are suitable for new contributors](https://github.com/apache/tooling-trusted-releases/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22) as `good first issue`. These are typically small, well-defined tasks that do not require deep familiarity with the entire codebase. Working on one of these issues is an excellent way to learn how ATR works and how we develop it.

If you find a bug that is not already reported in the issue tracker, or if you have an idea for a new feature, please [create a new issue](https://github.com/apache/tooling-trusted-releases/issues/new) to discuss it with other developers before you start working on it. This helps to ensure that your contribution will be accepted, and that you do not duplicate work that is already in progress. For small changes such as fixing typographical errors or improving documentation clarity, you do not need to create an issue first.

## Pull request workflow

Once you have identified something to work on, the process of contributing is as follows:

1. **Fork the repository.** Create a personal fork of the [ATR repository](https://github.com/apache/tooling-trusted-releases) on GitHub.

2. **Clone your fork.** Clone your fork to your local machine and set up your development environment. Follow the instructions in the [running the server](running-the-server) guide to get ATR running locally. Please [ask us for help](#getting-help) if you encounter any problems with this step.

3. **Create a branch.** [Create a new branch](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-and-deleting-branches-within-your-repository) for your work. Use a descriptive name that indicates what you are working on, such as `fix-typo-in-docs` or `improve-error-messages`.

4. **Make your changes.** Implement your fix or feature, following our [code conventions](code-conventions). If you are changing code, ensure that your changes do not break existing functionality. If you are adding a new feature, consider whether tests are appropriate.

5. **Commit your changes.** Write clear, concise commit messages following [our commit message style](#commit-message-style). Each commit should represent a logical unit of work, but we are not particularly strict about this.

6. **Push your branch.** Push your branch to your fork on GitHub.

7. **Create a pull request (PR).** The PR should be from your branch to the `main` branch of the ATR repository. In the PR description, explain what your changes do and why they are needed. If your PR addresses an existing issue, reference that issue by number.

8. **Participate in code review.** A member of the Tooling team will review your PR and may request changes. _We strongly recommend enabling the option to allow maintainers to edit your PR when you create it._ Even if you allow us to make changes, we may still ask you to make the changes yourself. Also, because of the stringent security and usability requirements for ATR, we accept only [high quality contributions](#special-considerations-for-atr).

You can also [email patches](https://lists.apache.org/list.html?dev@tooling.apache.org) if you prefer not to use GitHub. Please use standard Git patch formatting, as if you were e.g. contributing to the Linux Kernel.

## Commit message style

We follow a consistent style for commit messages. The first line of the commit message is called the subject line, and should follow these guidelines:

- **Use the imperative mood.** The subject line should complete the sentence "If applied, this commit will...".
- **Use sentence case.** Start with a capital letter, but do not use a full stop at the end.
- **Use articles as appropriate before nouns**. Write about "a feature" not just "feature". Say, for example, "fix a bug", and not "fix bug".
- **Be specific and descriptive.** Prefer "Fix a bug in vote resolution for tied votes" to "Fix a bug" or "Update the vote code".
- **Keep it concise.** Aim for 50 to 72 characters. If you need more space to explain your changes, use the commit body.

**Examples of good subject lines:**

```
Add distribution platform validation to the compose phase
Fix a bug with sorting version numbers containing release candidates
Move code to delete releases to the storage interface
Update dependencies
```

**Examples of poor subject lines:**

```
fixed stuff
Updated the code.
refactoring vote resolution logic
```

Most commits do not need a body. The subject line alone is sufficient for small, focused changes. If, however, your commit is complex or requires additional explanation, add a body separated from the subject line by a blank line. In the body, explain what the change does and why it was necessary. We typically use itemized lists for this, using asterisks. You do not need to explain how the change works.

## ASF contribution policies

As an Apache Software Foundation project, ATR follows the standard ASF contribution and licensing policies. These policies ensure that the ASF has the necessary rights to distribute your contributions, and that contributors retain their rights to use their contributions for other purposes.

### Contributor License Agreement

Before we can accept your first contribution as an individual contributor, you must sign the [Apache Individual Contributor License Agreement](https://www.apache.org/licenses/contributor-agreements.html#clas) (ICLA). This is a one-time requirement, and you do not need to sign a new ICLA for each contribution. The ICLA grants the ASF the right to distribute and build upon your work within Apache, while you retain full rights to use your original contributions for any other purpose. The ICLA is not a copyright assignment. You can find detailed instructions for submitting the ICLA in the [ASF new committers guide](https://infra.apache.org/new-committers-guide.html#submitting-your-individual-contributor-license-agreement-icla).

If your employer holds rights to your work, then you may also need to submit a [Corporate Contributor License Agreement](https://www.apache.org/licenses/contributor-agreements.html#clas) (CCLA). Please consult with your employer to determine whether this is necessary.

### Licensing

All contributions to ATR are licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). By submitting a pull request, you agree that your contributions will be licensed under this license. If you include any third party code or dependencies in your contribution, you must ensure that they are compatible with the Apache License 2.0. The ASF maintains a list of [Category A licenses](https://www.apache.org/legal/resolved.html#category-a) that are compatible, and [Category X licenses](https://www.apache.org/legal/resolved.html#category-x) that are not compatible.

### Code of conduct

All contributors to ATR are expected to follow the [ASF Code of Conduct](https://www.apache.org/foundation/policies/conduct.html), and any other applicable policies of the ASF.

## Special considerations for ATR

ATR is developed by ASF Tooling, which is an initiative of the ASF rather than a top-level project (TLP). This means that ATR follows the development processes and governance structure of Tooling, which may differ slightly from those of other ASF projects. There are also significant security considerations for ATR, which places additional requirements on contributions.

### Security focus

The primary goal of ATR is to deter and minimize supply chain attacks on ASF software releases. Since security is our highest priority, we scrutinize all contributions for potential vulnerabilities. To assist us when you make a contribution, please:

- Follow secure coding practices. Review best practice guidelines to learn how to avoid vulnerabilities such as injection attacks, cross-site scripting, and insecure deserialization.
- Validate all user inputs and sanitize all outputs.
- Use well established, independently audited, and actively maintained libraries rather than implementing cryptographic or security sensitive functionality yourself.
- Always consider the security implications of your changes. If you are unsure of the implications of your changes, ask the team for guidance.
- Report any security issues you discover in ATR responsibly. Do not open a public issue for security vulnerabilities. Instead, follow the [ASF security reporting process](https://www.apache.org/security/).

### High quality standards

Because of the critical nature of ATR, we maintain very high standards for code quality. This means that the review process may take longer than you expect, and we may request more extensive changes than you are accustomed to. We appreciate your patience and understanding. Our goal is to ensure that ATR remains as secure and reliable as possible.

### Access controls

We strongly encourage all contributors to enable two-factor authentication on their GitHub accounts, preferably with a [passkey](https://en.wikipedia.org/wiki/WebAuthn#Passkey_branding).

## Getting help

If you have questions about contributing to ATR, or if you need help with any step of the contribution process, please reach out to the team. You can:

- Ask questions on the [dev mailing list](https://lists.apache.org/list.html?dev@tooling.apache.org), which is the primary forum for ATR development discussions.
- Comment on the relevant issue or pull request in the [issue tracker](https://github.com/apache/tooling-trusted-releases/issues).
- Chat with us in the [#apache-trusted-releases channel](https://the-asf.slack.com/archives/C049WADAAQG) on ASF Slack.
- Read the rest of the [developer guide](developer-guide) for detailed information about how ATR works and how to make changes to it.

We welcome all types of contribution, and are happy to help you get started. Thank you for your interest in contributing to ATR.
