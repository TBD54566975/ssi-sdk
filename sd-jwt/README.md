[![godoc ssi-sdk](https://img.shields.io/badge/godoc-ssi--sdk-blue)](https://pkg.go.dev/github.com/TBD54566975/ssi-sdk/sd-jwt)
[![go version 1.20.3](https://img.shields.io/badge/go_version-1.20.4-brightgreen)](https://golang.org/)
[![Go Report Card A+](https://goreportcard.com/badge/github.com/TBD54566975/ssi-sdk/sd-jwt)](https://goreportcard.com/report/github.com/TBD54566975/ssi-sdk/sd-jwt)
[![license Apache 2](https://img.shields.io/badge/license-Apache%202-black)](https://github.com/TBD54566975/ssi-sdk/blob/main/LICENSE)

# SD-JWT support in golang

`sd-jwt` is a library that implements the IETF draft for [Selective Disclosure for JWTs](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html).
This library facilitates creating combined formats for issuance and presentation with arbitrary payloads, and performing
verification from the holder or from the verifiers perspective.

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [Building](#building)

## Installation

To install `sd-jwt`, use `go get`:

```bash
go get github.com/TBD54566975/ssi-sdk/sd-jwt
```

## Quick Start
See [this example](example/main.go).

You can run it by cloning this repo, changing directory into this directory, and running a go application.
See the terminal command below. 

```shell
git clone github.com/TBD54566975/ssi-sdk.git
cd ssi-sdk/sd-jwt
go run example.main.go
```

## Usage
The best usage examples can be found in the [sd_jwt_test.go](sd_jwt_test.go) file.

## API Reference
See our [oficial godocs](https://pkg.go.dev/github.com/TBD54566975/ssi-sdk/sd-jwt).

## Configuration
Configuration is done via dependency injection on the `SDJWTSigner` struct. 

If you want to inject your own implementation of JWT signatures, you can pass it by implementing a struct that satisfies
the `Signer` interface. 

If you want to inject your own random number generator, you can pass it by implementation the `SaltGenerator` interface.
We provide a default one which relies on `crypto/rand`, which you can instantiate by calling `NewSaltGenerator`.

## Building 
See the [SDK Building](../README.md#building) section.

## Contributing
See the general [CONTRIBUTING](../CONTRIBUTING.md) guide.

## Issues
See current issues [here](https://github.com/TBD54566975/ssi-sdk/issues?q=is%3Aissue+is%3Aopen+label%3Asd-jwt). 
