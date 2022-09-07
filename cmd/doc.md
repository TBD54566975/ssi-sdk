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

*What prior information outside of this spec is useful or necessary to understand this proposal?*

Issue around buildling a CLI: https://github.com/TBD54566975/ssi-sdk/issues/150

*What are the pre-requisites that need to be true for this work to succeed?*

The cli tool must be self-contained and leverage the SSI-SDK's for operations.
It shall not be a daemon and only runs when invoked. It can use a datastore for
key management, etc.

## Goals

*What is the purpose of this SIP? In bullet form, what are the goals and non-goals for this work?*

* Create various DID's with using different key types.
* Expand and resolve DID's that are self resolvable.
* Sign a did document
* Unsign a did document
* Validate a did document
* Message a did document
* Key management

## Specification

*Main area for going into your proposal, technical details with diagrams as necessary. It is ok to list multiple possible options, and outline your recommendation.*

Commands can be combined together to form an action. Example:

```
./cli create did -kt "Ed25519"
```

### First Order Commands

* create
* update
* get
* delete

### Second Order Commands

* did
* vc
* key
* vp
* ps

### Options

* --keytype -kt = "key type"
* -v = "verbose"

### High level outline

Commands can be combined together to form an action. Example:

```
./cli create did -kt "Ed25519"
```

## Considerations

* Modularity of component

### Tradeoffs

### Failure Modes & Mitigations

### Dependencies 

###  Future Work

### Security & Privacy

## Release 

### Success Criteria

## References







