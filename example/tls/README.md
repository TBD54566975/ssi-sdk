# Secure TLS Communication with Self-Signed Certificates and DID Integration

## Overview

This Go application showcases secure communication over a network using TLS (Transport Layer Security) with dynamically generated self-signed X.509 certificates. It integrates Decentralized Identifiers (DIDs) for unique identity representation, leveraging the SSI (Self-Sovereign Identity) SDK for cryptographic operations and DID resolution. The application consists of a TLS server and a TLS client, demonstrating encrypted message exchange.


## TL;DR

Run this example by doing `go run main.go` from this folder. The expected result is below:
```
$ go run main.go
Server: Listening on localhost:8443
Client: Verifying peer certificate
Server: Received 'Hello from Client'
Client: Received 'Hello from Server'
```

## Key Features

- **TLS Server and Client Implementation**: Establishes a simple TLS server and client that securely exchange messages over the network.
- **Dynamic Self-Signed Certificate Generation**: Automatically generates RSA private keys and the corresponding self-signed X.509 certificates, incorporating DIDs into the certificates' subject fields.
- **DID-Based Identity**: Utilizes DIDs to uniquely identify server and client entities, converting RSA public keys into JWK (JSON Web Key) format and further into DID-based JWKs for enhanced identity management.
- **Encrypted Communication**: Ensures all communications between the server and client are encrypted and authenticated through TLS, offering privacy and data integrity.

> [!NOTE]
> Private keys can easily be switched to any supported key type.

> [!NOTE]
> Other did methods besides JWK can be easily supported by adding additional resolvers. 

## Functionality

### Initialization

- Upon execution, the application initializes both the TLS server and client in separate goroutines, enabling concurrent operation.
- The server listens on `localhost:8443`, ready to accept client connections.

### RSA Keys and Certificate Generation

- Both server and client generate their RSA private keys and use them to create self-signed certificates. The certificates embed DIDs in their common names, facilitating secure TLS connections with identity verification.

### Conversion to JWK and DID

- The application converts public RSA keys to JWK format, subsequently transforming them into DID-based JWKs using functionalities provided by the `ssi-sdk`.
- The conversion process links TLS identities (as represented by the certificates) with decentralized identities (DIDs), showcasing a modern approach to identity management.

### Certificate Verification

During the TLS handshake, the client verifies the server's certificate against a list of trusted Certificate Authorities (CAs). Since the application uses self-signed certificates, the following custom verification logic is applied:

- **InsecureSkipVerify**: Set to `true` to bypass the default certificate verification process, and overrides `VerifyPeerCertificate` as shown below.
- **VerifyPeerCertificate**: A custom callback function provided to the TLS client's configuration. It implements additional verification checks on the peer's certificate.

### Custom Verification Logic

The custom verification logic includes:

1. **Certificate Parsing**: Parses the peer's certificate to extract critical information, including the subject's Common Name (CN), which contains the DID.
1. **DID Resolution**: Utilizes the SSI SDK to resolve the DID embedded in the certificate's CN to a public key. This step simulates the process of fetching the corresponding public key from a decentralized identity document.
1. **Public Key Matching**: Compares the resolved public key against the public key embedded in the certificate to ensure they match. This confirms that the certificate is indeed associated with the DID it claims to represent.
1. **Integrity Check**: Verifies that the certificate's signature is valid and that it has not been tampered with. This ensures the integrity of the certificate and the authenticity of its issuer (in this case, self-issued).


### Secure Message Exchange

- Following the establishment of a secure TLS channel, the client sends a greeting message to the server, which responds accordingly.
- The exchange demonstrates the application's capability to facilitate secure, encrypted communications over TLS.

## Dependencies

- **Go Standard Libraries (`crypto/x509`, `crypto/tls`, etc.)**: Used for cryptographic functions and TLS communication.
- **SSI SDK (`github.com/TBD54566975/ssi-sdk/crypto/jwx`, `github.com/TBD54566975/ssi-sdk/did/jwk`, etc.)**: Utilized for DID to JWK conversion and cryptographic operations.

## Getting Started

1. Ensure Go is installed on your system and your GOPATH is correctly set up.
2. Clone the repository and navigate to the project directory.
3. Run `go run main.go` to start the server and client.
4. Observe the encrypted message exchange between the server and client in the terminal.

## Security Considerations

This example uses self-signed certificates for simplicity and demonstration purposes. In a production environment, certificates should be obtained from a trusted Certificate Authority (CA) to ensure widespread trust and compatibility. The application exemplifies the integration of TLS security mechanisms with DIDs, suitable for secure communication in various applications, including decentralized systems and IoT devices.

For feedback and contributions, please open an issue or submit a pull request.
