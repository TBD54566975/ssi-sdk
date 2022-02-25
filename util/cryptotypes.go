package util

// Exists to remove cyclic dependencies

type (
	KeyType       string
	SignatureType string
	ProofPurpose  string
)

const (
	JsonWebKey2020 KeyType = "JsonWebKey2020"
)
