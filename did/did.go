package did

type Method string

const (
	KeyMethod  Method = "key"
	PeerMethod Method = "peer"
	PKHMethod  Method = "pkh"
	WebMethod  Method = "web"
)

// DID represents functionality common to all DIDs
type DID interface {
	// IsValid checks if the DID is compliant with its methods definition
	IsValid() bool
	// ToString Returns the string representation of the DID identifier (e.g. did:example:abcd)
	ToString() string
	// Suffix provides the value of the DID without the method prefix
	Suffix() (string, error)
	// Method provides the method for the DID
	Method() Method
}

// ResolutionOptions https://www.w3.org/TR/did-spec-registries/#did-resolution-options
type ResolutionOptions interface{}

// Resolver provides an interface for resolving DIDs as per the spec
// https://www.w3.org/TR/did-core/#did-resolution
type Resolver interface {
	Resolve(d DID, opts ResolutionOptions) (*DIDDocument, *DIDResolutionMetadata, *DIDDocumentMetadata, error)
}
