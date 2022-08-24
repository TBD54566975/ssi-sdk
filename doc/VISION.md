# Vision

Name `ssi-sdk`, this SDK encapsulates a set of standards related to [Self Sovereign Identity](http://www.lifewithalacrity.com/2016/04/the-path-to-self-soverereign-identity.html). The `ssi-sdk` intends to provide flexible functionality based on a set of standards-based primitives for building decentralized identity applications in a modular manner: with limited dependencies between components.

Primarily, the SDK serves to support Decentralized Identifiers and Verifiable Credentials and their associated standards. Interacting with Decentralized Identifiers: resolving identifiers, signing, verifying, encrypting, and decrypting data using cryptographic keys found in DID Documents. Interacting with Verifiable Credentials: creating and using data schemas, facilitating credential application, issuance, and exchange.

The SSI SDK is closely related to the [SSI Service](https://github.com/TBD54566975/ssi-service), where much of its features are exposed in a service infrastructure.

# Guiding Principles

The SDK is a core component of Web5 and has a guiding principle to *build pragmatic standards-based software that serves a wide variety of needs*. The software shall not be tied to any specific entity, nor, without good reason, exclude possibilities within the SSI space. Balancing both feature-richness and complexity we must work closely with our users to design software that meets the needs of all who wish to be on Web5. We favor evaluating the addition of features and standards on a case-by-case basis, and looking towards implementations of standards and features that are well-reasoned, with committed developers. Bonus points if there is already demonstrated usage and interoperability.

## Feature Support

The feature set of the SDK is largely influenced by the standards and specifications in the Decentralized Identity community in aim of advancing the adoption of Self Sovereign Identity. We favor evaluating the addition of features and standards on a case-by-case basis, and looking towards implementations of standards and features that are well-reasoned, with committed developers and use cases. Features that already demonstrated usage and interoperability outside of the project are prime candidates for adoption.

## Language Support

The SSI ecosystem uses a wide set of tools, languages, and technologies: working across web browsers, mobile applications, backend servers, ledgers, and more. This SDK uses [Go](https://go.dev/) because of its robust cryptographic support, speed, ability to be compiled to [WASM](https://webassembly.org/), and, above all else, simplicity. It is crucial that the code we write is approachable to encourage contribution. Simple and clear is always preferred over clever. 

The future is multi-language, and multi-platform. We welcome initiatives for improving multi-language and multi-platform support, and are open to incubating them in our GitHub organization. When future SDKs are developed, it is expected that they follow the same feature set and API as the Go SDK in addition to fulfilling the suite of language interoperability tests.