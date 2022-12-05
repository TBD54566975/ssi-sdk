# CLI Tool

**Title:** Cli Tool Specifications  
**Author(s):** Andor Kesselman, Gabe Cohen, Neal Roessler  
**Status:** Draft  
**Created:** September 7, 2022  
**Updated:** September 7, 2022  
**Version** 0.0.1

## Abstract

The description here is the scope, vision, flow, and usage of the cli tool for
the ssi-sdk. It is intended to be the guiding framework for the cli tool.

## Background

_What prior information outside of this spec is useful or necessary to understand this proposal?_

Issue around buildling a CLI: https://github.com/TBD54566975/ssi-sdk/issues/150

_What are the pre-requisites that need to be true for this work to succeed?_

The cli tool must be self-contained and leverage the SSI-SDK's for operations.
It shall not be a daemon and only runs when invoked. It can use a datastore for
key management, etc.

## Goals

_What is the purpose of this SIP? In bullet form, what are the goals and non-goals for this work?_

- Create various DID's with using different key types.
- Expand and resolve DID's that are self resolvable.
- Sign a did document
- Unsign a did document
- Validate a did document
- Message a did document
- Key management

## Specification

_Main area for going into your proposal, technical details with diagrams as necessary. It is ok to list multiple possible options, and outline your recommendation._

Commands can be combined together to form an action. Example:

```
./cli create did -kt "Ed25519"
```

### First Order Commands

- create
- update
- get
- delete

### Second Order Commands

- did
- vc
- key
- vp
- ps

### Options

- --keytype -kt = "key type"
- -v = "verbose"

### High level outline

Commands can be combined together to form an action. Example:

```
./cli create did -kt "Ed25519"
```

## Considerations

- Modularity of component
- Easy to extend
- Clarity

### Dependencies

There are a [few major cli tools for golang that can be built](https://mt165.co.uk/blog/golang-cli-library/)

We will use `cobra` for the cli. Why?

- it's super popular, and more likely to have more familiarity
- it's a little heavier weight than some other cli frameworks, but it probably
  does everything we will ever need
- it speeds up development time

### Future Work

- For alpha, we scope this to basic operations already provided in the SDK.
- For beta, we will migrate this to move to ssi-service and support service
  commands as well.

### Security & Privacy

## Release

- Alpha:
  - Basic operations over cli. DID Creation, etc.
- Beta:
  - Migrate and merge with ssi service, to add additional service commands to
    the cli
