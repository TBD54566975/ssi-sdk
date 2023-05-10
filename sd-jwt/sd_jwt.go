package sdjwt

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	mathrand "math/rand"
	"strings"

	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

const (
	sdClaimName    = "_sd"
	sdAlgClaimName = "_sd_alg"
	sha256Alg      = "sha-256"
)

// CreatePresentation creates the Combined Format for Presentation as specified in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-combined-format-for-present
// jwtAndDisclosures is a Combined Format for Issuance as specified in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-combined-format-for-issuanc.
// disclosuresToPresent is a set of which the indices of the disclosures that the presentation should contain.
// holderBindingJWT may be empty. It's a JWT with the claims `nonce` and `aud` in them. It's proof shows that this
// presentation is intended for the Verifier, while also preventing replay attacks.
func CreatePresentation(jwtAndDisclosures []byte, disclosuresToPresent []int, holderBindingJWT []byte) []byte {
	sdParts := bytes.Split(jwtAndDisclosures, []byte("~"))

	elems := [][]byte{sdParts[0]}
	for _, disclosureIdx := range disclosuresToPresent {
		elems = append(elems, sdParts[disclosureIdx+1])
	}

	elems = append(elems, holderBindingJWT)

	return bytes.Join(elems, []byte("~"))
}

type saltGenerator struct {
	NumBytes int
}

func NewSaltGenerator(numBytes int) SaltGenerator {
	return &saltGenerator{
		NumBytes: numBytes,
	}
}

// Generate returns a base64 url encoded string that of NumBytes bytes that are cryptographically random.
func (g saltGenerator) Generate() (string, error) {
	data := make([]byte, g.NumBytes)
	_, err := rand.Read(data)
	if err != nil {
		return "", errors.Wrap(err, "reading random data")
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// SaltGenerator generates a cryptographically random string.
type SaltGenerator interface {
	Generate() (string, error)
}

type disclosureFactory struct {
	saltGen SaltGenerator
}

// FromClaimAndValue creates a Disclosure from the given claim name, and the associated value. The salt value will be
// set from the SaltGenerator. claimValue will be marshalled to JSON encoded data.
func (d disclosureFactory) FromClaimAndValue(claim string, claimValue any) (*Disclosure, error) {
	saltValue, err := d.saltGen.Generate()
	if err != nil {
		return nil, err
	}

	return &Disclosure{
		Salt:       saltValue,
		ClaimName:  claim,
		ClaimValue: claimValue,
	}, nil
}

// BlindOption is an interface to encapsulate the different blinding options for nested data in SD-JWTs as described in
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-nested-data-in-sd-jwts
type BlindOption interface{}

// FlatBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-1-flat-sd-jwt
type FlatBlindOption struct {
	BlindOption
}

// SubClaimBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-2-structured-sd-jwt
type SubClaimBlindOption struct {
	claimsToBlind map[string]BlindOption
	BlindOption
}

// RecursiveBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-3-sd-jwt-with-recurs
type RecursiveBlindOption struct {
	BlindOption
}

// claimSetBlinder is a struct to help go from a regular JWT to an SD-JWT.
type claimSetBlinder struct {
	sdAlg             HashFunc
	disclosureFactory disclosureFactory

	// totalDigests is used to determine the total number of decoy digests to add. This function received the number of
	// real digests, and returns the total number to digests that should be present.
	totalDigests func(int) int
}

// blindElementsRecurvisely returns the blinded version for each element.
func (csb claimSetBlinder) blindElementsRecurvisely(elems []any) ([]any, []Disclosure, error) {
	var blinded []any
	var allDisclosures []Disclosure
	for i, elem := range elems {
		claimsToBlind := make(map[string]BlindOption)

		switch m := elem.(type) {
		case map[string]any:
			for k := range m {
				claimsToBlind[k] = RecursiveBlindOption{}
			}

			blindedValue, ds, err := csb.toBlindedClaimsAndDisclosures(m, claimsToBlind)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "blinding element at index %d", i)
			}
			blinded = append(blinded, blindedValue)
			allDisclosures = append(allDisclosures, ds...)
		case []any:
			blindedValue, ds, err := csb.blindElementsRecurvisely(m)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "blinding element at index %d", i)
			}
			blinded = append(blinded, blindedValue)
			allDisclosures = append(allDisclosures, ds...)
		default:
			blinded = append(blinded, m)
		}
	}
	return blinded, allDisclosures, nil
}

// toBlindedClaimsAndDisclosures returns a blinded map that can be marshalled to JSON along with the disclosures.
// The input claims represents a struct from unmarshalled JSON-encoded data. The claimsToBlind is used to determine how
// to blind the values.
func (csb claimSetBlinder) toBlindedClaimsAndDisclosures(
	claims map[string]any,
	claimsToBlind map[string]BlindOption,
) (map[string]any, []Disclosure, error) {
	blindedClaims := make(map[string]any)
	var allDisclosures []Disclosure
	var hashedDisclosures []string

	for claimName, claimValue := range claims {
		blindOption, ok := claimsToBlind[claimName]
		if !ok {
			blindedClaims[claimName] = claimValue
			continue
		}

		switch b := blindOption.(type) {
		case FlatBlindOption:
			disclosure, err := csb.disclosureFactory.FromClaimAndValue(claimName, claimValue)
			if err != nil {
				return nil, nil, err
			}

			allDisclosures = append(allDisclosures, *disclosure)
			hashedDisclosures = append(hashedDisclosures, disclosure.Digest(csb.sdAlg))
		case SubClaimBlindOption:
			switch claimValueTyped := claimValue.(type) {
			case map[string]any:
				blindedSubClaim, subClaimDisclosures, err := csb.toBlindedClaimsAndDisclosures(claimValueTyped, b.claimsToBlind)
				if err != nil {
					return nil, nil, err
				}
				blindedClaims[claimName] = blindedSubClaim
				allDisclosures = append(allDisclosures, subClaimDisclosures...)
			default:
				return nil, nil, errors.New("blind option not applicable to non object types")
			}

		case RecursiveBlindOption:
			var disclosure *Disclosure
			switch vv := claimValue.(type) {

			case []any:
				blindedSubClaims, subClaimDisclosure, err := csb.blindElementsRecurvisely(vv)
				if err != nil {
					return nil, nil, err
				}

				allDisclosures = append(allDisclosures, subClaimDisclosure...)

				disclosure, err = csb.disclosureFactory.FromClaimAndValue(claimName, blindedSubClaims)
				if err != nil {
					return nil, nil, err
				}
			case map[string]any:
				subClaimsToBlind := make(map[string]BlindOption, len(vv))
				for k := range vv {
					subClaimsToBlind[k] = RecursiveBlindOption{}
				}

				blindedSubClaims, subClaimDisclosure, err := csb.toBlindedClaimsAndDisclosures(vv, subClaimsToBlind)
				if err != nil {
					return nil, nil, err
				}

				allDisclosures = append(allDisclosures, subClaimDisclosure...)

				disclosure, err = csb.disclosureFactory.FromClaimAndValue(claimName, blindedSubClaims)
				if err != nil {
					return nil, nil, err
				}
			default:
				var err error
				disclosure, err = csb.disclosureFactory.FromClaimAndValue(claimName, claimValue)
				if err != nil {
					return nil, nil, err
				}
			}
			allDisclosures = append(allDisclosures, *disclosure)
			hashedDisclosures = append(hashedDisclosures, disclosure.Digest(csb.sdAlg))
		}
	}

	// Add some decoy hashed disclosures
	totalHashed := csb.totalDigests(len(hashedDisclosures))
	for i := len(hashedDisclosures); i < totalHashed; i++ {
		randBytes := make([]byte, 32)
		if _, err := rand.Read(randBytes); err != nil {
			return nil, nil, errors.Wrap(err, "reading random bytes")
		}
		digest := csb.sdAlg(randBytes)
		hashedDisclosures = append(hashedDisclosures, base64.RawURLEncoding.EncodeToString(digest[:]))
	}

	// Shuffle a bit, so we don't even disclose any ordering
	mathrand.Shuffle(len(hashedDisclosures), func(i, j int) {
		hashedDisclosures[i], hashedDisclosures[j] = hashedDisclosures[j], hashedDisclosures[i]
	})

	blindedClaims[sdClaimName] = hashedDisclosures
	return blindedClaims, allDisclosures, nil
}

// SDJWTSigner is a struct that facilitates creating the combined format for issuance of SD-JWTs.
type SDJWTSigner struct {
	disclosureFactory disclosureFactory
	signer            Signer
}

type Signer interface {
	Sign(blindedClaimsData []byte) ([]byte, error)
}

// NewSDJWTSigner creates an SDJWTSigner with a default configuration. It uses the passed in signer to sign payloads.
func NewSDJWTSigner(signer Signer, saltGenerator SaltGenerator) *SDJWTSigner {
	return &SDJWTSigner{
		disclosureFactory: disclosureFactory{
			saltGen: saltGenerator,
		},
		signer: signer,
	}
}

// BlindAndSign returns an SD-JWT and Disclosures from an arbitrary JSON-encoded payload. The claims to selectively
// disclose are determined using the claimsToBlind map. The format of the result is the Combined Format for Issuance
// as specified in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-combined-format-for-issuanc
func (s SDJWTSigner) BlindAndSign(claimsData []byte, claimsToBlind map[string]BlindOption) ([]byte, error) {
	var claimsMap map[string]any
	if err := json.Unmarshal(claimsData, &claimsMap); err != nil {
		return nil, errors.Wrap(err, "unmarshalling claims")
	}
	csb := claimSetBlinder{
		sdAlg:             sha256Digest,
		disclosureFactory: s.disclosureFactory,
		totalDigests:      getNextPowerOfTwo,
	}
	blindedClaims, disclosures, err := csb.toBlindedClaimsAndDisclosures(claimsMap, claimsToBlind)
	if err != nil {
		return nil, errors.Wrap(err, "blinding claims")
	}

	blindedClaims[sdAlgClaimName] = sha256Alg
	blindedClaimsData, err := json.Marshal(blindedClaims)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling blinded claims")
	}

	signed, err := s.signer.Sign(blindedClaimsData)
	if err != nil {
		return nil, errors.Wrap(err, "signing blinded claims")
	}

	return createIssuance(signed, disclosures)
}

func getNextPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}

	return int(math.Pow(2, math.Ceil(math.Log2(float64(n+1)))))
}

func sha256Digest(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

// GetHashAlg returns the hashFunc specified in the token.
func GetHashAlg(t jwt.Token) (HashFunc, error) {
	hashName := sha256Alg
	if t != nil {
		if hashNameValue, ok := t.Get(sdAlgClaimName); ok {
			hashName, ok = hashNameValue.(string)
			if !ok {
				return nil, errors.New("converting _sd_alg claim value to string")
			}
		}
	}

	switch hashName {
	case sha256Alg:
		return sha256Digest, nil
	default:
		return nil, errors.Errorf("unsupported hash name %q", hashName)
	}
}

type HolderBindingOption bool

const (
	VerifyHolderBinding     HolderBindingOption = true
	SkipVerifyHolderBinding                     = false
)

type Disclosure struct {
	Salt       string
	ClaimName  string
	ClaimValue any
}

// Digest returns the digest according to https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-hashing-disclosures
func (d Disclosure) Digest(hashAlg HashFunc) string {
	e, err := d.EncodedDisclosure()
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(hashAlg([]byte(e)))
}

// EncodedDisclosure returns the base64 url safe encoding of this disclosure.
func (d Disclosure) EncodedDisclosure() (string, error) {
	value, err := json.Marshal(d.ClaimValue)
	if err != nil {
		return "", errors.Wrap(err, "marshalling claim value")
	}
	jsonEncoded := []byte(fmt.Sprintf(`[%q, %q, %s]`, d.Salt, d.ClaimName, value))

	return base64.RawURLEncoding.EncodeToString(jsonEncoded), nil
}

type HashFunc func([]byte) []byte

func parseDisclosures(disclosuresData []string, hashAlg HashFunc) (map[string]*Disclosure, error) {
	ds := make([]*Disclosure, 0, len(disclosuresData))
	for _, dd := range disclosuresData {
		d, err := parseDisclosure(dd)
		if err != nil {
			return nil, errors.Wrapf(err, "parsing disclosure %q", dd)
		}
		ds = append(ds, d)
	}
	disclosureDigests := make(map[string]*Disclosure, len(ds))
	//For each Disclosure provided:
	for _, disclosure := range ds {
		// Calculate the digest over the base64url-encoded string as described in Section 5.1.1.2.
		disclosureDigests[disclosure.Digest(hashAlg)] = disclosure
	}
	return disclosureDigests, nil
}

func parseDisclosure(encodedDisclosure string) (*Disclosure, error) {
	disclosureJSON, err := base64.RawURLEncoding.DecodeString(encodedDisclosure)
	if err != nil {
		return nil, errors.Wrap(err, "decoding disclosure")
	}
	var disclosureElems []any
	if err := json.Unmarshal(disclosureJSON, &disclosureElems); err != nil {
		return nil, errors.Wrap(err, "unmarshalling disclosure")
	}
	// If the Disclosure is not a JSON-encoded array of three elements, the Verifier MUST reject the Presentation.
	if len(disclosureElems) != 3 {
		return nil, errors.New("disclosure must have exactly 3 elements")
	}

	// Insert, at the level of the _sd key, a new claim using the claim name and claim value from the Disclosure.
	// If the claim name already exists at the same level, the Verifier MUST reject the Presentation.
	disclosureClaimName, ok := disclosureElems[1].(string)
	if !ok {
		return nil, errors.New("second element of disclosure must by a string")
	}
	return &Disclosure{
		Salt:       disclosureElems[0].(string),
		ClaimName:  disclosureClaimName,
		ClaimValue: disclosureElems[2],
	}, nil
}

type VerificationOptions struct {
	holderBindingOption           HolderBindingOption
	alg                           string
	issuerKey                     any
	desiredNonce, desiredAudience string
	resolveHolderKey              func(jwt.Token) gocrypto.PublicKey
}

// VerifySDPresentation takes in a combined presentation format as defined in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-combined-format-for-present
// and Verifies it according to https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-verification-by-the-verifie
// Succesful verifications return a processed SD-JWT payload.
// TODO(https://github.com/TBD54566975/ssi-sdk/issues/378): only accept certain algos for validating the JWT, and the holder binding JWT
func VerifySDPresentation(presentation []byte, verificationOptions VerificationOptions) (map[string]any, error) {
	// 2. Separate the Presentation into the SD-JWT, the Disclosures (if any), and the Holder Binding JWT (if provided).
	sdParts := strings.Split(string(presentation), "~")

	// Validate the SD-JWT:
	//
	//Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [RFC8725], Sections 3.1 and 3.2 for details. The none algorithm MUST NOT be accepted.
	//Validate the signature over the SD-JWT.
	//Validate the Issuer of the SD-JWT and that the signing key belongs to this Issuer.
	//Check that the SD-JWT is valid using nbf, iat, and exp claims, if provided in the SD-JWT, and not selectively disclosed.
	sdToken, err := jwt.Parse([]byte(sdParts[0]), jwt.WithKey(jwa.KeyAlgorithmFrom(verificationOptions.alg), verificationOptions.issuerKey), jwt.WithValidate(true))
	if err != nil {
		return nil, errors.Wrap(err, "parsing jwt")
	}

	//Check that the _sd_alg claim value is understood and the hash algorithm is deemed secure.
	hashAlg, err := GetHashAlg(sdToken)
	if err != nil {
		return nil, err
	}

	n := len(sdParts) - 1
	// For each Disclosure provided calculate the digest over the base64url-encoded string as described in Section 5.1.1.2.
	disclosuresByDigest, err := parseDisclosures(sdParts[1:n], hashAlg)
	if err != nil {
		return nil, err
	}

	// Process the Disclosures and _sd keys in the SD-JWT as follows:
	//
	//Create a copy of the SD-JWT payload, if required for further processing.
	tokenClaims, err := sdToken.AsMap(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "gathering token map")
	}

	if err := processPayload(tokenClaims, disclosuresByDigest, map[string]struct{}{}); err != nil {
		return nil, err
	}

	if verificationOptions.holderBindingOption == VerifyHolderBinding {
		// If Holder Binding JWT is not provided, the Verifier MUST reject the Presentation.
		holderBindingJWT := sdParts[len(presentation)-1]
		if len(holderBindingJWT) == 0 {
			return nil, errors.New("holder binding required, but holder binding JWT not found")
		}

		// Determine the public key for the Holder from the SD-JWT.
		holderKey := verificationOptions.resolveHolderKey(sdToken)

		//Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [RFC8725], Sections 3.1 and 3.2 for details. The none algorithm MUST NOT be accepted.
		//TODO(https://github.com/TBD54566975/ssi-sdk/issues/377): support holder binding properly as specified in RFC7800. Alg should be coming from CNF.
		holderBindingAlg := jwa.ES256K

		//Validate the signature over the Holder Binding JWT.
		//Check that the Holder Binding JWT is valid using nbf, iat, and exp claims, if provided in the Holder Binding JWT.
		//Determine that the Holder Binding JWT is bound to the current transaction and was created for this Verifier (replay protection). This is usually achieved by a nonce and aud field within the Holder Binding JWT.
		holderBindingToken, err := jwt.Parse([]byte(holderBindingJWT), jwt.WithKey(holderBindingAlg, holderKey), jwt.WithValidate(true))
		if err != nil {
			return nil, errors.Wrap(err, "parsing and validating holder binding jwt")
		}

		nonce, ok := holderBindingToken.Get("nonce")
		if !ok {
			return nil, errors.New("nonce must be present in holder binding jwt")
		}
		if nonce != verificationOptions.desiredNonce {
			return nil, errors.New("nonce found does not match desiredNonce")
		}

		audienceFound := false
		for _, audience := range holderBindingToken.Audience() {
			if audience == verificationOptions.desiredAudience {
				audienceFound = true
				break
			}
		}
		if !audienceFound {
			return nil, errors.New("desired audience not found")
		}
	}
	return tokenClaims, nil
}

// processPayload will recursively remove all _sd fields from the claims object, and replace it with the information
// found inside disclosuresByDigest.
func processPayload(claims map[string]any, disclosuresByDigest map[string]*Disclosure, digestsFound map[string]struct{}) error {

	//Find all _sd keys in the SD-JWT payload. For each such key perform the following steps (*):
	for _, claimValue := range claims {
		switch claimMap := claimValue.(type) {
		case map[string]any:
			if err := processPayload(claimMap, disclosuresByDigest, digestsFound); err != nil {
				return err
			}
		}
	}
	sdClaimValue, ok := claims[sdClaimName]
	if !ok {
		return nil
	}

	//  If the key does not refer to an array, the Verifier MUST reject the Presentation.
	sdDigests, ok := sdClaimValue.([]any)
	if !ok {
		return errors.New("_sd key MUST refer to an array")
	}

	newClaims := make(map[string]any)
	for _, digestValue := range sdDigests {
		digest, ok := digestValue.(string)
		if !ok {
			return errors.New("digest must be a string")
		}

		// Compare the value with the digests calculated previously and find the matching Disclosure. If no such Disclosure can be found, the digest MUST be ignored.
		disclosure, ok := disclosuresByDigest[digest]
		if !ok {
			continue
		}

		// If any digests were found more than once, the Verifier MUST reject the Presentation.
		if _, ok := digestsFound[digest]; ok {
			return errors.Errorf("digest %q found more than once", digest)
		}
		digestsFound[digest] = struct{}{}

		if _, ok := newClaims[disclosure.ClaimName]; ok {
			return errors.Errorf("claim name %q already exists", disclosure.ClaimName)
		}
		if _, ok := claims[disclosure.ClaimName]; ok {
			return errors.Errorf("claim name %q already exists", disclosure.ClaimName)
		}
		newClaims[disclosure.ClaimName] = disclosure.ClaimValue

		//  If the decoded value contains an _sd key in an object, recursively process the key using the steps described in (*).
		if decodedClaim, ok := disclosure.ClaimValue.(map[string]any); ok {
			if err := processPayload(decodedClaim, disclosuresByDigest, digestsFound); err != nil {
				return err
			}
		}
	}

	delete(claims, sdClaimName)
	delete(claims, sdAlgClaimName)
	for k, v := range newClaims {
		claims[k] = v
	}

	return nil
}

type IssuanceVerificationOptions struct {
	alg       string
	issuerKey gocrypto.PublicKey
}

// VerifyIssuance returns an error whenever any of the following happens for the given combined format for issuance:
// 1. The SD-JWT cannot be verified with the given key and algorithm.
// 2. There is a disclosure with a digest that is not included in any of the digests of the JWT, nor of the disclosures.
// This function is intented to aid with https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-processing-by-the-holder
func VerifyIssuance(issuance []byte, verificationOptions IssuanceVerificationOptions) error {
	issuanceParts := strings.Split(string(issuance), "~")
	sdToken, err := jwt.Parse([]byte(issuanceParts[0]), jwt.WithKey(jwa.SignatureAlgorithm(verificationOptions.alg), verificationOptions.issuerKey), jwt.WithValidate(true))
	if err != nil {
		return errors.Wrap(err, "parsing jwt")
	}

	tokenClaims, err := sdToken.AsMap(context.Background())
	if err != nil {
		return errors.Wrap(err, "getting token claim map")
	}

	//Check that the _sd_alg claim value is understood and the hash algorithm is deemed secure.
	hashAlg, err := GetHashAlg(sdToken)
	if err != nil {
		return err
	}

	// For each Disclosure provided calculate the digest over the base64url-encoded string as described in Section 5.1.1.2.
	disclosuresByDigest, err := parseDisclosures(issuanceParts[1:], hashAlg)
	if err != nil {
		return err
	}

	allDigests := make(map[string]struct{})
	for _, d := range getDigests(tokenClaims) {
		allDigests[d] = struct{}{}
	}
	for _, disclosure := range disclosuresByDigest {
		for _, d := range getDigests(disclosure.ClaimValue) {
			allDigests[d] = struct{}{}
		}
	}

	// Check whether all disclosure digests are contained
	for digest := range disclosuresByDigest {
		if _, ok := allDigests[digest]; !ok {
			return errors.Errorf("digest %q not found", digest)
		}
	}
	return nil
}

func getDigests(claims any) []string {
	switch c := claims.(type) {
	case map[string]any:
		return getDigestsForMap(c)
	case []any:
		return getDigestsForSlice(c)
	}
	return nil
}

func getDigestsForSlice(c []any) []string {
	var digests []string
	for _, v := range c {
		digests = append(digests, getDigests(v)...)
	}
	return digests
}

func getDigestsForMap(c map[string]any) []string {
	var digests []string
	for k, v := range c {
		if k == sdClaimName {
			for _, vv := range v.([]any) {
				digests = append(digests, vv.(string))
			}
		} else {
			digests = append(digests, getDigests(v)...)
		}
	}
	return digests
}

// createIssuance returns the combined format for issuance
func createIssuance(sdJWT []byte, disclosures []Disclosure) ([]byte, error) {
	elems := [][]byte{sdJWT}
	for _, d := range disclosures {
		ed, err := d.EncodedDisclosure()
		if err != nil {
			return nil, err
		}
		elems = append(elems, []byte(ed))
	}
	return bytes.Join(elems, []byte("~")), nil
}
