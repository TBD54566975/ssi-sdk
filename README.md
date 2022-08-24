[![godoc ssi-sdk](https://img.shields.io/badge/godoc-ssi--sdk-blue)](https://pkg.go.dev/github.com/TBD54566975/ssi-sdk)
[![go version 1.17.6](https://img.shields.io/badge/go_version-1.17.6-brightgreen)](https://golang.org/)
[![Go Report Card A+](https://goreportcard.com/badge/github.com/TBD54566975/ssi-sdk)](https://goreportcard.com/report/github.com/TBD54566975/ssi-sdk)
[![license Apache 2](https://img.shields.io/badge/license-Apache%202-black)](https://github.com/TBD54566975/ssi-sdk/blob/main/LICENSE)
[![issues](https://img.shields.io/github/issues/TBD54566975/ssi-sdk)](https://github.com/TBD54566975/ssi-sdk/issues)
![ssi-sdk-ci status](https://github.com/TBD54566975/ssi-sdk/workflows/ssi-sdk-ci/badge.svg?branch=main&event=push)

# ssi-sdk

# Introduction

Named `ssi-sdk`, this SDK encapsulates a set of standards related
to [Self Sovereign Identity](http://www.lifewithalacrity.com/2016/04/the-path-to-self-soverereign-identity.html).
The `ssi-sdk` intends to provide flexible functionality based on a set of standards-based primitives for building
decentralized identity applications in a modular manner: with limited dependencies between components.

![ssi-sdk](doc/ssi-sdk.png)

The image above outlines the SDK's vision. Standards may be added and/or removed. The standards themselves are under
active development, and as such, are subject to change. When possible we aim to call out which versions or revisions of
standards we are building implementations against.

The SDK has not undergone any formal security review or audit, so please use with caution.

For more information, see the [vision document](doc/VISION.md).

# Contributing

This project is fully open source, and we welcome contributions! For more information please see
[CONTRIBUTING](https://github.com/TBD54566975/ssi-sdk/blob/main/CONTRIBUTING.md). Our current thinking about the
development of the library is captured in
[GitHub Issues](https://github.com/TBD54566975/ssi-sdk/issues).

# Specifications

Here are a set of references to specifications that this library currently supports. It is a dynamic set that will
change as the library evolves.

- [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/2021/PR-did-core-20210803/) _W3C Proposed Recommendation
  03 August 2021_
- [Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/2021/REC-vc-data-model-20211109/) _W3C Recommendation
  09 November 2021_
    - Supports [Linked Data Proof](https://www.w3.org/TR/vc-data-model/#data-integrity-proofs) formats.
    - Supports [VC-JWT and VP-JWT](https://www.w3.org/TR/vc-data-model/#json-web-token) formats.
- [Verifiable Credentials JSON Schema Specification](https://w3c-ccg.github.io/vc-json-schemas/v2/index.html) _Draft
  Community Group Report, 21 September 2021_
- [Presentation Exchange 2.0.0](https://identity.foundation/presentation-exchange/) _Working Group Draft, March 2022_
- [Wallet Rendering](https://identity.foundation/wallet-rendering) _Strawman, June 2022_
- [Credential Manifest](https://identity.foundation/credential-manifest/) _Strawman, June 2022_
- [Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021/) _Draft Community Group Report 04 April 2022_

## signature suites

- [Data Integrity 1.0](https://w3c-ccg.github.io/data-integrity-spec) _Draft Community Group Report_
- [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/) _Draft Community Group
  Report 29 December 2020_
- [JSON Web Signature 2020](https://w3c-ccg.github.io/lds-jws2020) _Draft Community Group Report 09 February 2022_
    - [VC Proof Formats Test Suite, VC Data Model with JSON Web Signatures](https://identity.foundation/JWS-Test-Suite/)
      _Unofficial Draft 09 March 2022_
      This implementation's compliance with the JWS Test
      Suite [can be found here](https://identity.foundation/JWS-Test-Suite/#tbd).
    - Supports both JWT and Linked Data proof formats with [JOSE compliance](https://jose.readthedocs.io/en/latest/).

## did methods

- [The did:key Method v0.7](https://w3c-ccg.github.io/did-method-key/) _Unofficial Draft 14 February 2022_
- [The did:web Method](https://w3c-ccg.github.io/did-method-web/) _20 December 2021_
- [The did:peer Method](https://identity.foundation/peer-did-method-spec/) _W3C Document 12 October 2021_
- [The did:pkh Method](https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md) _Draft, 22 August 2022_

# Building

This project uses [mage](https://magefile.org/), please
view [CONTRIBUTING](https://github.com/TBD54566975/ssi-sdk/blob/main/CONTRIBUTING.md) for more information.

After installing mage, you can build and test the SDK with the following commands:

```
mage build
mage test
```

A utility is provided to run _clean, build, and test_ in sequence with:

```
mage cbt
```

# Versioning

For information on versioning refer to our [versioning guide](doc/VERSIONING.md).

The latest version is...nothing! No releases have been made.

# Examples

A set of code examples can be found in the [examples directory](example). We welcome
contributions for additional examples.

- [Decentralized Identifiers Example](example/did)
- [Verifiable Credentials Example](example/vc)
- [Presentation Exchange Example](example/use_case/apartment_application)

# Project Resources

| Resource                                                                               | Description                                                                   |
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [VISION](https://github.com/TBD54566975/ssi-sdk/blob/main/doc/VISION.md)               | Outlines the project vision                                                   |
| [VERSIONING](https://github.com/TBD54566975/ssi-sdk/blob/main/doc/VERSIONING.md)       | Project versioning strategy                                                   |
| [CODE_OF_CONDUCT](https://github.com/TBD54566975/ssi-sdk/blob/main/CODE_OF_CONDUCT.md) | Expected behavior for project contributors, promoting a welcoming environment |
| [CONTRIBUTING](https://github.com/TBD54566975/ssi-sdk/blob/main/CONTRIBUTING.md)       | Developer guide to build, test, run, access CI, chat, discuss, file issues    |
| [GOVERNANCE](https://github.com/TBD54566975/ssi-sdk/blob/main/GOVERNANCE.md)           | Project governance                                                            |
| [LICENSE](https://github.com/TBD54566975/ssi-sdk/blob/main/LICENSE)                    | Apache License, Version 2.0                                                   |
