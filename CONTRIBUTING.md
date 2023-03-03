# Contribution Guide

There are many ways to be an open source contributor, and we're here to help you on your way! You may:

* Propose ideas in our [discussion forums](https://forums.tbd.website/)
* Raise an issue or feature request in our [issue tracker](https://github.com/TBD54566975/ssi-sdk/issues)
* Help another contributor with one of their questions, or a code review
* Suggest improvements to our Getting Started documentation by supplying a Pull Request
* Evangelize our work together in conferences, podcasts, and social media spaces.

This guide is for you.

## Development Prerequisites

| Requirement | Tested Version | Installation Instructions                              |
|-------------|----------------|--------------------------------------------------------|
| Go          | 1.20.1         | [go.dev](https://go.dev/doc/tutorial/compile-install)  |
| Mage        | 1.13.0-6       | [magefile.org](https://magefile.org/)                  |

### Go

This project is written in Go, a modern, open source programming language.

You may verify your `go` installation via the terminal:

```
$> go version
go version go1.20.1 darwin/amd64
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

---
## Communications

### Issues

Anyone from the community is welcome (and encouraged!) to raise issues
via [GitHub Issues](https://github.com/TBD54566975/ssi-sdk/issues).

### Discussions

Design discussions and proposals take place on the [TBD Forum](https://forums.tbd.website/).

We advocate an asynchronous, written debate model - so write up your thoughts and invite the community to join in!

### Continuous Integration

Build and Test cycles are run on every commit to every branch
using [GitHub Actions](https://github.com/TBD54566975/ssi-sdk/actions).

## Contribution
---

We review contributions to the codebase via GitHub's Pull Request mechanism. We have the following guidelines to ease
your experience and help our leads respond quickly to your valuable work:

### Code
* All new code and PRs should follow [Uber's Go Style guide](https://github.com/uber-go/guide/blob/master/style.md).
* All new tests should follow unit test [best practices from Microsoft](https://learn.microsoft.com/en-us/dotnet/core/testing/unit-testing-best-practices#best-practices). 

### Process
* Start by proposing a change either in Issues (most appropriate for small change requests or bug fixes) or in
  Discussions (most appropriate for design and architecture considerations, proposing a new feature, or where you'd like
  insight and feedback)
* Cultivate consensus around your ideas; the project leads will help you pre-flight how beneficial the proposal might be
  to the project. Developing early buy-in will help others understand what you're looking to do, and give you a greater
  chance of your contributions making it into the codebase! No one wants to see work done in an area that's unlikely to
  be incorporated into the codebase.
* Fork the repo into your own namespace/remote
* Work in a dedicated feature branch. Atlassian wrote a
  great [description of this workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/feature-branch-workflow)
* When you're ready to offer your work to the project, first:
* Squash your commits into a single one (or an appropriate small number of commits), and rebase atop the upstream `main`
  branch. This will limit the potential for merge conflicts during review, and helps keep the audit trail clean. A good
  writeup for how this is done
  is [here](https://medium.com/@slamflipstrom/a-beginners-guide-to-squashing-commits-with-git-rebase-8185cf6e62ec), and
  if you're having trouble - feel free to ask a member or the community for help or leave the commits as-is, and flag
  that you'd like rebasing assistance in your PR! We're here to support you.
* Open a PR in the project to bring in the code from your feature branch.
* The maintainers noted in the `CODEOWNERS` file will review your PR and optionally open a discussion about its contents
  before moving forward.
* Remain responsive to follow-up questions, be open to making requested changes, and...
* You're a contributor!
* And remember to respect everyone in our global development community. Guidelines are established in
  our `CODE_OF_CONDUCT.md`.
