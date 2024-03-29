package main

import (
	"context"
	gocrypto "crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/jwk"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
)

const (
	addr = "localhost:8443"
)

func main() {
	var wg sync.WaitGroup

	// Start TLS server
	wg.Add(1)
	go func() {
		defer wg.Done()
		startTLSServer()
	}()

	// Give the server a moment to start
	wg.Add(1)
	go func() {
		defer wg.Done()
		startTLSClient()
	}()

	wg.Wait()
}

func startTLSServer() {
	_, privateKey, err := crypto.GenerateRSA2048Key()
	if err != nil {
		panic(err)
	}

	publicJwk, err := jwx.PublicKeyToPublicKeyJWK(nil, privateKey.Public())
	if err != nil {
		log.Fatal(err)
	}

	didJwk, err := jwk.CreateDIDJWK(*publicJwk)
	if err != nil {
		log.Fatal(err)
	}

	// Define the subject details for the certificate.
	subject := pkix.Name{
		SerialNumber: "1234",
		CommonName:   didJwk.String(),
	}
	certPem, err := GenerateSelfSignedCert(&privateKey, privateKey.Public(), subject)
	if err != nil {
		panic(err)
	}

	// Marshal the private key to its ASN.1 PKCS#1 DER encoded form
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(&privateKey)

	// Create a PEM block with the private key
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	cer, err := tls.X509KeyPair(certPem, privateKeyPEM)
	if err != nil {
		log.Fatal(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	fmt.Println("Server: Listening on " + addr)
	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Fatal(err)
		}
	}
	fmt.Printf("Server: Received '%s'\n", string(buffer[:n]))
	_, err = conn.Write([]byte("Hello from Server"))
	if err != nil {
		log.Fatal(err)
	}
}

func startTLSClient() {
	// Give the server time to start
	time.Sleep(1 * time.Second)

	_, privateKey, err := crypto.GenerateRSA2048Key()
	if err != nil {
		panic(err)
	}

	publicJwk, err := jwx.PublicKeyToPublicKeyJWK(nil, privateKey.Public())
	if err != nil {
		log.Fatal(err)
	}

	didJwk, err := jwk.CreateDIDJWK(*publicJwk)
	if err != nil {
		log.Fatal(err)
	}

	// Define the subject details for the certificate.
	subject := pkix.Name{
		SerialNumber: "5678",
		CommonName:   didJwk.String(),
	}
	certPem, err := GenerateSelfSignedCert(&privateKey, privateKey.Public(), subject)
	if err != nil {
		panic(err)
	}

	// Marshal the private key to its ASN.1 PKCS#1 DER encoded form
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(&privateKey)

	// Create a PEM block with the private key
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	cert, err := tls.X509KeyPair(certPem, privateKeyPEM)
	if err != nil {
		log.Fatal(err)
	}

	config := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, // Only use this for testing with self-signed certs!
		VerifyPeerCertificate: verifyPeerCertificate,
	}

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Hello from Client"))
	if err != nil {
		log.Fatal(err)
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Client: Received '%s'\n", string(buffer[:n]))
}

func verifyPeerCertificate(certs [][]byte, chains [][]*x509.Certificate) error {
	fmt.Println("Client: Verifying peer certificate")

	if chains != nil {
		return errors.New("verifying peer certificate: chains expected to be nil")
	}

	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return errors.New("parsing certificate")
	}

	opts := x509.VerifyOptions{
		Roots: x509.NewCertPool(),
	}
	opts.Roots.AddCert(cert)

	_, err = cert.Verify(opts)
	if err != nil {
		return errors.New("verifying peer: " + err.Error())
	}

	if cert.Subject.CommonName != cert.Issuer.CommonName {
		return errors.New("common name of subject and issuer aren't equal")
	}

	fromDid, err := certPublicKeyFromDid(cert.Subject.CommonName, jwk.Resolver{})
	if err != nil {
		return err
	}

	jwkFromCert, err := jwx.PublicKeyToPublicKeyJWK(nil, cert.PublicKey)
	if err != nil {
		return err
	}
	if *jwkFromCert == *fromDid {
		return nil
	}

	return errors.New("verifying peer certificate failed")
}

func certPublicKeyFromDid(did string, resolver resolution.Resolver) (*jwx.PublicKeyJWK, error) {
	// resolve the did
	result, err := resolver.Resolve(context.Background(), did)
	if err != nil {
		return nil, err
	}

	// Assume there is a verification method, and use that to get the public key of the cert.
	return result.Document.VerificationMethod[0].PublicKeyJWK, nil
}

// GenerateSelfSignedCert generates a self-signed X.509 certificate for a given RSA private key and subject details.
// Returns the certificate and any error encountered.
func GenerateSelfSignedCert(privateKey gocrypto.PrivateKey, publicKey gocrypto.PublicKey, subject pkix.Name) ([]byte, error) {
	// Set certificate's serial number to a random big integer.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Prepare certificate template.
	certTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the self-signed certificate.
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, publicKey, privateKey)
	if err != nil {
		return nil, errors.New("creating certificate: " + err.Error())
	}

	// Encode the certificate into PEM format.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	return certPEM, nil
}
