package ion

type ErrorCode string

const (
	DeltaExceedsMaximumSize                    ErrorCode = "DeltaExceedsMaximumSize"
	DIDDocumentPublicKeyIDDuplicated           ErrorCode = "DidDocumentPublicKeyIdDuplicated"
	DIDDocumentPublicKeyMissingOrIncorrectType ErrorCode = "DidDocumentPublicKeyMissingOrIncorrectType"
	DIDDocumentServiceIDDuplicated             ErrorCode = "DidDocumentServiceIdDuplicated"
	DIDSuffixIncorrectLength                   ErrorCode = "DidSuffixIncorrectLength" // #nosec
	EncodedStringIncorrectEncoding             ErrorCode = "EncodedStringIncorrectEncoding"
	IDNotUsingBase64URLCharacterSet            ErrorCode = "IdNotUsingBase64UrlCharacterSet"
	IDTooLong                                  ErrorCode = "IdTooLong"
	JWKES256kMissingOrInvalidCRV               ErrorCode = "JwkEs256kMissingOrInvalidCrv"
	JWKES256kMissingOrInvalidKTY               ErrorCode = "JwkEs256kMissingOrInvalidKty"
	JWKES256kHasIncorrectLengthOfX             ErrorCode = "JwkEs256kHasIncorrectLengthOfX"
	JWKES256kHasIncorrectLengthOfY             ErrorCode = "JwkEs256kHasIncorrectLengthOfY"
	JWKES256kHasIncorrectLengthOfD             ErrorCode = "JwkEs256kHasIncorrectLengthOfD"
	MultihashStringNotAMultihash               ErrorCode = "MultihashStringNotAMultihash"
	MultihashUnsupportedHashAlgorithm          ErrorCode = "MultihashUnsupportedHashAlgorithm"
	PublicKeyJWKES256kHasUnexpectedProperty    ErrorCode = "PublicKeyJwkEs256kHasUnexpectedProperty"
	PublicKeyPurposeDuplicated                 ErrorCode = "PublicKeyPurposeDuplicated"
	ServiceEndpointCannotBeAnArray             ErrorCode = "ServiceEndpointCannotBeAnArray"
	ServiceEndpointStringNotValidURI           ErrorCode = "ServiceEndpointStringNotValidUri"
	ServiceTypeTooLong                         ErrorCode = "ServiceTypeTooLong"
)
