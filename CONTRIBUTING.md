# Contribution Guide

This repo acts as a one-stop, opinionated toolkit for all things Self Sovereign Identity (SSI). Before contributing, we recommend that you review the [README](README.md), dig into some of the specifications it mentions, take a look at recent PRs, and issues. The SDK is intended to be used in any go project. Our [SSI Service](github.com/TBD54566975/ssi-service) makes use of the SDK for much of its core functionality.

When you're ready you may:
* Propose ideas in our SSI [discord](https://discord.com/channels/937858703112155166/969272692891086868) channel
* Raise an issue or feature request in our [issue tracker](https://github.com/TBD54566975/ssi-sdk/issues)
* Help another contributor with one of their questions, or a code review


## Development Prerequisites

| Requirement | Tested Version | Installation Instructions                              |
|-------------|----------------|--------------------------------------------------------|
| Go          | 1.22.1         | [go.dev](https://go.dev/doc/tutorial/compile-install)  |
| Mage        | 1.13.0-6       | [magefile.org](https://magefile.org/)                  |

### Go

This project is written in [Go](https://go.dev/), a modern, open source programming language. Go was chosen because of its speed, simplicity, and versatility. Go is a powerful language that's easy to pick up. It works across ecosystems, and even works with WASM.

You may verify your `go` installation via the terminal:

```
$> go version
go version go1.22.1 darwin/amd64
```

If you do not have go, we recommend installing it by:

#### MacOS

##### Homebrew

```
$> brew install go
```

### Mage

The build is run by Mage.

You may verify your `mage` installation via the terminal:

```
$> mage --version
Mage Build Tool v1.13.0-6-g051a55c
Build Date: 2022-05-02T19:53:34-07:00
Commit: 051a55c
built with: go1.17.6
```

#### MacOS

##### Homebrew

```
$> brew install mage
```

---

## Build (Mage)

```
$> mage build
```

## Test (Mage)

```
$> mage test
```

### Clean / Build / Test (Mage)

```
$> mage cbt
```

---

## Communications

### Issues

Anyone from the community is welcome (and encouraged!) to raise issues
via [GitHub Issues](https://github.com/TBD54566975/ssi-sdk/issues).

We label issues according to their functionality (e.g. `dids`, `sign-verify`, `credentials`, `bug`, `documentation`, `testing` and more). If you don't see an appropriate label for an issue feel free to request a new one. 

We use [GitHub Projects](https://github.com/orgs/TBD54566975/projects/17) to track our work.

### Discussions

Design discussions and proposals take place in our SSI [discord](https://discord.com/channels/937858703112155166/969272692891086868) channel.

We advocate an asynchronous, written debate model - so write up your thoughts and invite the community to join in!

### Continuous Integration

Build and Test cycles are run on every commit to every branch
using [GitHub Actions](https://github.com/TBD54566975/ssi-sdk/actions).

## Contribution

We review contributions to the codebase via GitHub's Pull Request mechanism. We have the following guidelines to ease
your experience and help our leads respond quickly to your valuable work:

### Code
* All new code and PRs should follow [Uber's Go Style guide](https://github.com/uber-go/guide/blob/master/style.md).
* All new tests should follow unit test [best practices from Microsoft](https://learn.microsoft.com/en-us/dotnet/core/testing/unit-testing-best-practices#best-practices). 

### Process
We suggest the following process when picking up an issue:
 * Check to see if anyone is already working on the issue by looking to see if the issue has any comments saying so.
 * Fork the repo and create a branch containing the issue number you're working on
 * Push that branch and create a PR, mentioning the issue it relates to in the description.
 * You may also choose to paste a link to the PR in the original issue.

If you don't see an issue for what you would like to work on, have an idea for a new features found a bug, or have a question...
* Start by proposing a change either in [GitHub Issues](https://github.com/TBD54566975/ssi-sdk/issues) or on our Discord in the `#ssi` channel
* Fork the repo into your own namespace/remote
* Work in a dedicated feature branch. Atlassian wrote a
  great [description of this workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/feature-branch-workflow)
* When you're ready to offer your work to the project:
  * Open a PR in the project to bring in the code from your feature branch.
  * The maintainers noted in the `CODEOWNERS` file will review your PR and work with you to get it merged.
