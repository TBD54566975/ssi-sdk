package sdjwt

import (
	"bytes"
	gocrypto "crypto"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type mockGenerator struct {
	values []string
	i      int
}

func (m *mockGenerator) Generate() (string, error) {
	if m.values != nil {
		temp := m.values[m.i%len(m.values)]
		m.i++
		return temp, nil
	}
	return "_26bc4LT-ac6q2KI6cBW5es", nil
}

func TestDisclosure_EncodedDisclosure(t *testing.T) {
	b := disclosureFactory{saltGen: &mockGenerator{}}
	disclosure, err := b.FromClaimAndValue("family_name", "Möbius")
	assert.NoError(t, err)

	got, err := disclosure.EncodedDisclosure()
	assert.NoError(t, err)
	assert.Equal(t, "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0", got)
}

func TestDisclosure_Digest(t *testing.T) {
	b := disclosureFactory{saltGen: &mockGenerator{}}
	disclosure, err := b.FromClaimAndValue("family_name", "Möbius")
	assert.NoError(t, err)

	got := disclosure.Digest(sha256Digest)

	assert.Equal(t, "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0", got)
}

func TestGetHashAlg(t *testing.T) {
	gotAlg, err := GetHashAlg(nil)
	assert.NoError(t, err)
	got := gotAlg([]byte("WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"))
	assert.Equal(t, "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY", base64.RawURLEncoding.EncodeToString(got))
}

func TestSDJWTSigner_BlindAndSign(t *testing.T) {
	subjectPrivKey, subjectDID, err := key.GenerateDIDKey(crypto.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, subjectPrivKey)
	assert.NotEmpty(t, subjectDID)
	issuerSigner := createSigner(t)

	claims := []byte(`{
  "sub": "john_doe_42",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "recursive": {
    "recursive.a": "hello_rec",
    "recursive.b": "world_rec"
  },
  "subclaim": {
    "a": "hello",
    "b": "world"
  },
  "birthdate": "1940-01-01",
  "some_numbers_i_like": [1, {"deeply":"nested"}, 7, 8]
}`)
	claimsToBlind := map[string]BlindOption{
		"sub":          FlatBlindOption{},
		"given_name":   FlatBlindOption{},
		"family_name":  FlatBlindOption{},
		"email":        FlatBlindOption{},
		"phone_number": FlatBlindOption{},
		"address":      FlatBlindOption{},
		"birthdate":    FlatBlindOption{},
		"recursive":    RecursiveBlindOption{},
		"subclaim": SubClaimBlindOption{
			claimsToBlind: map[string]BlindOption{
				"a": FlatBlindOption{},
				"b": FlatBlindOption{},
			},
		},
		"some_numbers_i_like": RecursiveBlindOption{},
	}

	signer := SDJWTSigner{
		disclosureFactory: disclosureFactory{
			saltGen: &mockGenerator{},
		},
		signer: &lestratSigner{
			*issuerSigner,
		},
	}
	sdJWT, err := signer.BlindAndSign(claims, claimsToBlind)
	assert.NoError(t, err)

	jwtAndDisclosures := strings.Split(string(sdJWT), "~")
	assert.Len(t, jwtAndDisclosures, 15)

	jwtParts := strings.Split(jwtAndDisclosures[0], ".")
	assert.Len(t, jwtParts, 3)

	claimsetJSON, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	assert.NoError(t, err)

	var claimset map[string]any
	assert.NoError(t, json.Unmarshal(claimsetJSON, &claimset))

	assert.Len(t, claimset["_sd"], 16)
	assert.Equal(t, "sha-256", claimset["_sd_alg"])

	assert.NotContains(t, claimset, "sub")
	assert.NotContains(t, claimset, "given_name")
	assert.NotContains(t, claimset, "John")
	assert.NotContains(t, claimset, "family_name")
	assert.NotContains(t, claimset, "Doe")
	assert.NotContains(t, claimset, "email")
	assert.NotContains(t, claimset, "johndoe@example.com")
	assert.NotContains(t, claimset, "phone_number")
	assert.NotContains(t, claimset, "+1-202-555-0101")
	assert.NotContains(t, claimset, "birthdate")
	assert.NotContains(t, claimset, "1940-01-01")
	assert.NotContains(t, claimset, "recursive")
	assert.NotContains(t, claimset, "some_numbers_i_like")
	assert.Contains(t, claimset, "subclaim")
	assert.Len(t, claimset["subclaim"].(map[string]any)["_sd"], 4)

	gotDisclosures := make(map[string]any, len(jwtAndDisclosures))
	for _, encodedDisclosure := range jwtAndDisclosures[1:] {
		decodedDisclosure, err := base64.RawURLEncoding.DecodeString(encodedDisclosure)
		assert.NoError(t, err)

		var disclosure []any
		assert.NoError(t, json.Unmarshal(decodedDisclosure, &disclosure))

		gotDisclosures[disclosure[1].(string)] = disclosure[2]
	}

	assert.Equal(t, "john_doe_42", gotDisclosures["sub"])
	assert.Equal(t, "John", gotDisclosures["given_name"])
	assert.Equal(t, "Doe", gotDisclosures["family_name"])
	assert.Equal(t, "johndoe@example.com", gotDisclosures["email"])
	assert.Equal(t, "+1-202-555-0101", gotDisclosures["phone_number"])
	assert.Equal(t, "1940-01-01", gotDisclosures["birthdate"])
	assert.Equal(t, "hello", gotDisclosures["a"])
	assert.Equal(t, "world", gotDisclosures["b"])
	assert.Len(t, gotDisclosures["recursive"].(map[string]any)["_sd"], 4)
	assert.Equal(t, "hello_rec", gotDisclosures["recursive.a"])
	assert.Equal(t, "world_rec", gotDisclosures["recursive.b"])
	assert.Equal(t, map[string]any{
		"street_address": "123 Main St",
		"locality":       "Anytown",
		"region":         "Anystate",
		"country":        "US",
	}, gotDisclosures["address"])
	assert.Len(t, gotDisclosures["some_numbers_i_like"].([]any)[1].(map[string]any)["_sd"], 2)
	assert.Equal(t, "nested", gotDisclosures["deeply"])
}

func createSigner(t *testing.T) *jwx.Signer {
	issuerPrivKey, issuerDID, err := key.GenerateDIDKey(crypto.P256)
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerPrivKey)
	assert.NotEmpty(t, issuerDID)
	expandedIssuerDID, err := issuerDID.Expand()
	assert.NoError(t, err)
	assert.NotEmpty(t, expandedIssuerDID)
	issuerKID := expandedIssuerDID.VerificationMethod[0].ID
	assert.NotEmpty(t, issuerKID)

	issuerSigner, err := jwx.NewJWXSigner(issuerDID.String(), issuerKID, issuerPrivKey)
	assert.NoError(t, err)
	return issuerSigner
}

func TestGetpoweroftwo(t *testing.T) {
	assert.Equal(t, 8, getNextPowerOfTwo(6))
}

func TestCreatePresentation(t *testing.T) {
	{
		got := CreatePresentation([]byte(`somejwt~disclosure0~disclosure1~disclosure2`), []int{
			1,
			2,
		}, nil)
		want := []byte(`somejwt~disclosure1~disclosure2~`)
		assert.Equal(t, string(want), string(got))
	}
	{
		got := CreatePresentation([]byte(`somejwt~disclosure0~disclosure1~disclosure2`), []int{
			1,
		}, []byte(`amazeholderbindingjwt`))
		want := []byte(`somejwt~disclosure1~amazeholderbindingjwt`)
		assert.Equal(t, string(want), string(got))
	}
}

func TestVerifySDPresentation(t *testing.T) {
	jwtAndDisclosures, holderKey, issuerSigner := createCombinedIssuance(t)
	publicKeyJWK := issuerSigner.ToPublicKeyJWK()
	issuerKey, err := publicKeyJWK.ToPublicKey()
	assert.NoError(t, err)

	for _, tc := range []struct {
		name            string
		claimNames      map[string]struct{}
		expectedPayload map[string]any
	}{
		{
			name: "simple fields blinded",
			claimNames: map[string]struct{}{
				"sub":        {},
				"given_name": {},
			},
			expectedPayload: map[string]any{
				"sub":        "john_doe_42",
				"given_name": "John",
				"subclaim":   map[string]any{},
			},
		},
		{
			name: "subclaim blinding blinded",
			claimNames: map[string]struct{}{
				"a": {},
			},
			expectedPayload: map[string]any{
				"subclaim": map[string]any{
					"a": "hello",
				},
			},
		},
		{
			name: "recursive blinding of field",
			claimNames: map[string]struct{}{
				"recursive":   {},
				"recursive.a": {},
			},
			expectedPayload: map[string]any{
				"recursive": map[string]any{
					"recursive.a": "hello_rec",
				},
				"subclaim": map[string]any{},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sdPresentation := CreatePresentation(jwtAndDisclosures, selectDisclosures(t, jwtAndDisclosures, tc.claimNames), nil)

			processedPayload, err := VerifySDPresentation(sdPresentation,
				VerificationOptions{
					holderBindingOption: SkipVerifyHolderBinding,
					alg:                 issuerSigner.ALG,
					issuerKey:           issuerKey,
					desiredNonce:        "my_sample_nonce",
					desiredAudience:     "my_intended_aud",
					resolveHolderKey: func(token jwt.Token) any {
						return holderKey
					},
				})
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedPayload, processedPayload)
		})
	}
}

func selectDisclosures(t *testing.T, jwtAndDisclosures []byte, claimNames map[string]struct{}) []int {
	var idx []int
	for i, disclosure := range bytes.Split(jwtAndDisclosures, []byte("~"))[1:] {
		decoded, err := base64.RawURLEncoding.DecodeString(string(disclosure))
		assert.NoError(t, err)
		var values []any
		assert.NoError(t, json.Unmarshal(decoded, &values))
		if _, ok := claimNames[values[1].(string)]; ok {
			idx = append(idx, i)
		}
	}
	return idx
}

func createCombinedIssuance(t *testing.T) (sdJWT []byte, subjectPrivKey gocrypto.PrivateKey, signer *jwx.Signer) {
	subjectPrivKey, subjectDID, err := key.GenerateDIDKey(crypto.P256)
	assert.NoError(t, err)
	assert.NotEmpty(t, subjectPrivKey)
	assert.NotEmpty(t, subjectDID)
	issuerSigner := createSigner(t)

	claims := []byte(`{
  "sub": "john_doe_42",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "recursive": {
    "recursive.a": "hello_rec",
    "recursive.b": "world_rec"
  },
  "subclaim": {
    "a": "hello",
    "b": "world"
  },
  "birthdate": "1940-01-01"
}`)
	claimsToBlind := map[string]BlindOption{
		"sub":          FlatBlindOption{},
		"given_name":   FlatBlindOption{},
		"family_name":  FlatBlindOption{},
		"email":        FlatBlindOption{},
		"phone_number": FlatBlindOption{},
		"address":      FlatBlindOption{},
		"birthdate":    FlatBlindOption{},
		"recursive":    RecursiveBlindOption{},
		"subclaim": SubClaimBlindOption{
			claimsToBlind: map[string]BlindOption{
				"a": FlatBlindOption{},
				"b": FlatBlindOption{},
			},
		},
	}

	sdjwtSigner := SDJWTSigner{
		disclosureFactory: disclosureFactory{
			saltGen: &mockGenerator{},
		},
		signer: &lestratSigner{
			*issuerSigner,
		},
	}
	sdJWT, err = sdjwtSigner.BlindAndSign(claims, claimsToBlind)
	assert.NoError(t, err)
	return sdJWT, subjectPrivKey, issuerSigner
}

type lestratSigner struct {
	signer jwx.Signer
}

func (s lestratSigner) Sign(blindedClaimsData []byte) ([]byte, error) {
	insecureSDJWT, err := jwt.ParseInsecure(blindedClaimsData)
	if err != nil {
		return nil, errors.Wrap(err, "parsing blinded claims")
	}

	signed, err := jwt.Sign(insecureSDJWT, jwt.WithKey(jwa.KeyAlgorithmFrom(s.signer.ALG), s.signer.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "signing JWT credential")
	}
	return signed, nil
}

func identityFunc(i int) int {
	return i
}

func TestToBlindedClaimsAndDisclosures(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		claims                     []byte
		randomValue                string
		claimsToBlind              map[string]BlindOption
		expectedEncodedDigests     []string
		expectedDisclosure         Disclosure
		expectedPathEncodedDigests map[string]string
	}{
		{
			name: "flat with object",
			claims: []byte(`{
  "address": {
    "street_address": "Schulstr. 12",
    "locality": "Schulpforta",
    "region": "Sachsen-Anhalt",
    "country": "DE"
  }
}`),
			claimsToBlind: map[string]BlindOption{
				"address": FlatBlindOption{},
			},
			randomValue: "imQfGj1_M0El76kdvf7Daw",
			expectedDisclosure: Disclosure{
				Salt:      "imQfGj1_M0El76kdvf7Daw",
				ClaimName: "address",
				ClaimValue: map[string]any{
					"country":        "DE",
					"locality":       "Schulpforta",
					"region":         "Sachsen-Anhalt",
					"street_address": "Schulstr. 12",
				},
			},
		},
		{
			name: "flat with single value",
			claims: []byte(`{
  "time": "2012-04-23T18:25Z"
}`),
			randomValue: "cfYDJ3EGbELS2bHlMikCqA",
			claimsToBlind: map[string]BlindOption{
				"time": FlatBlindOption{},
			},
			expectedEncodedDigests: []string{"OSXqQur4cQzXkSlbTehtzOzsZBMgAIigvZmiNCV5Vd8"},
			expectedDisclosure: Disclosure{
				Salt:       "cfYDJ3EGbELS2bHlMikCqA",
				ClaimName:  "time",
				ClaimValue: "2012-04-23T18:25Z",
			},
		},
		{
			name: "subclaim with flat blinding of fields",
			claims: []byte(`{
  "address": {
    "street_address": "Schulstr. 12",
    "locality": "Schulpforta",
    "region": "Sachsen-Anhalt",
    "country": "DE"
  }
}`),
			randomValue: "QPkblxTnbSLL94I2fZIbHA",
			claimsToBlind: map[string]BlindOption{
				"address": SubClaimBlindOption{
					claimsToBlind: map[string]BlindOption{
						"locality": FlatBlindOption{},
					},
				},
			},
			expectedPathEncodedDigests: map[string]string{
				"$.address._sd": "KlG6HEM6XWbymEJDfyDY4klJkQQ9iTuNG0LQXnE9mQ0",
			},
			expectedDisclosure: Disclosure{
				Salt:       "QPkblxTnbSLL94I2fZIbHA",
				ClaimName:  "locality",
				ClaimValue: "Schulpforta",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			csb := claimSetBlinder{
				sdAlg:             sha256Digest,
				disclosureFactory: disclosureFactory{saltGen: &mockGenerator{values: []string{tc.randomValue}}},
				totalDigests:      identityFunc,
			}
			var claimMap map[string]any
			assert.NoError(t, json.Unmarshal(tc.claims, &claimMap))

			got, disclosures, err := csb.toBlindedClaimsAndDisclosures(claimMap, tc.claimsToBlind)
			assert.NoError(t, err)

			for _, expectedDigest := range tc.expectedEncodedDigests {
				assert.Contains(t, got["_sd"], expectedDigest)
			}

			blindedClaimSet, err := json.Marshal(got)
			assert.NoError(t, err)

			for path, expectedDigest := range tc.expectedPathEncodedDigests {
				p, err := json.CreatePath(path)
				assert.NoError(t, err)
				var v []any
				assert.NoError(t, p.Unmarshal(blindedClaimSet, &v))
				assert.Contains(t, v[0], expectedDigest)
			}
			assert.Equal(t, tc.expectedDisclosure.Salt, disclosures[0].Salt)
			assert.Equal(t, tc.expectedDisclosure.ClaimName, disclosures[0].ClaimName)
			assert.Equal(t, tc.expectedDisclosure.ClaimValue, disclosures[0].ClaimValue)
		})
	}

	csb := claimSetBlinder{
		sdAlg:             sha256Digest,
		disclosureFactory: disclosureFactory{saltGen: &mockGenerator{values: []string{"Fp0j-7zCaNTWf_wK67sxig"}}},
		totalDigests:      identityFunc,
	}

	t.Run("recursive blind fields", func(t *testing.T) {
		claims := []byte(`{
  "address": {
    "street_address": "Schulstr. 12",
    "locality": "Schulpforta",
    "region": "Sachsen-Anhalt",
    "country": "DE"
  }
}`)
		claimsToBlind := map[string]BlindOption{
			"address": RecursiveBlindOption{},
		}

		var claimMap map[string]any
		assert.NoError(t, json.Unmarshal(claims, &claimMap))

		got, disclosures, err := csb.toBlindedClaimsAndDisclosures(claimMap, claimsToBlind)
		assert.NoError(t, err)

		blindedClaimSetData, err := json.Marshal(got)
		assert.NoError(t, err)

		disclosuresByClaimName := make(map[string]Disclosure)
		for _, d := range disclosures {
			disclosuresByClaimName[d.ClaimName] = d
		}

		p, err := json.CreatePath("$._sd")
		assert.NoError(t, err)

		assert.Len(t, disclosures, 5)
		sdValue := disclosuresByClaimName["address"].ClaimValue.(map[string]any)["_sd"]
		assert.Len(t, sdValue, 4)
		assert.ElementsMatch(t, sdValue, []string{
			disclosuresByClaimName["street_address"].Digest(sha256Digest),
			disclosuresByClaimName["locality"].Digest(sha256Digest),
			disclosuresByClaimName["region"].Digest(sha256Digest),
			disclosuresByClaimName["country"].Digest(sha256Digest),
		})

		assert.Equal(t, "Schulstr. 12", disclosuresByClaimName["street_address"].ClaimValue)
		assert.Equal(t, "Schulpforta", disclosuresByClaimName["locality"].ClaimValue)
		assert.Equal(t, "Sachsen-Anhalt", disclosuresByClaimName["region"].ClaimValue)
		assert.Equal(t, "DE", disclosuresByClaimName["country"].ClaimValue)

		var v []any
		assert.NoError(t, p.Unmarshal(blindedClaimSetData, &v))
		assert.Len(t, v[0], 1)
	})

	t.Run("recursive with an array", func(t *testing.T) {
		claims := []byte(`{
  "address": {
    "street_address": [
      "Schulstr. 12",
      {
        "deep": "nested"
      }
    ]
  }
}`)
		claimsToBlind := map[string]BlindOption{
			"address": RecursiveBlindOption{},
		}

		var claimMap map[string]any
		assert.NoError(t, json.Unmarshal(claims, &claimMap))

		sdJWTClaimSet, disclosures, err := csb.toBlindedClaimsAndDisclosures(claimMap, claimsToBlind)
		assert.NoError(t, err)

		blindedClaimSetData, err := json.Marshal(sdJWTClaimSet)
		assert.NoError(t, err)

		p, err := json.CreatePath("$._sd")
		assert.NoError(t, err)

		var v []any
		assert.NoError(t, p.Unmarshal(blindedClaimSetData, &v))
		assert.Len(t, v[0], 1)

		disclosuresByClaimName := make(map[string]Disclosure)
		for _, d := range disclosures {
			disclosuresByClaimName[d.ClaimName] = d
		}

		assert.Len(t, disclosures, 3)
		assert.Equal(t, "nested", disclosuresByClaimName["deep"].ClaimValue)
		assert.Equal(t, map[string]any{
			"_sd": []string{
				disclosuresByClaimName["street_address"].Digest(sha256Digest),
			},
		}, disclosuresByClaimName["address"].ClaimValue)

		streetAddressArray := disclosuresByClaimName["street_address"].ClaimValue.([]any)
		assert.Equal(t, "Schulstr. 12", streetAddressArray[0])
		assert.Equal(t, disclosuresByClaimName["deep"].Digest(sha256Digest), streetAddressArray[1].(map[string]any)["_sd"].([]string)[0])

	})
}

func TestVerifyIssuance(t *testing.T) {
	issuerSigner := createSigner(t)
	publicKeyJwk := issuerSigner.ToPublicKeyJWK()
	issuerKey, err := publicKeyJwk.ToPublicKey()
	assert.NoError(t, err)
	signer := NewSDJWTSigner(&lestratSigner{
		*issuerSigner,
	}, NewSaltGenerator(16))

	t.Run("passes for a normal issuance", func(t *testing.T) {
		issuanceFormat, err := signer.BlindAndSign([]byte(`{"hello":"world"}`), map[string]BlindOption{
			"hello": RecursiveBlindOption{},
		})
		assert.NoError(t, err)

		err = VerifyIssuance(issuanceFormat, IssuanceVerificationOptions{
			alg:       issuerSigner.ALG,
			issuerKey: issuerKey,
		})
		assert.NoError(t, err)
	})

	t.Run("passes for a recursive issuance", func(t *testing.T) {
		issuanceFormat, err := signer.BlindAndSign([]byte(`{"hello":{"world":"yeah"}}`), map[string]BlindOption{
			"hello": RecursiveBlindOption{},
		})
		assert.NoError(t, err)

		err = VerifyIssuance(issuanceFormat, IssuanceVerificationOptions{
			alg:       issuerSigner.ALG,
			issuerKey: issuerKey,
		})
		assert.NoError(t, err)
	})

	t.Run("error is returned with a fake disclosure", func(t *testing.T) {
		fakeDisclosure := Disclosure{
			Salt:       "_26bc4LT-ac6q2KI6cBW5es",
			ClaimName:  "fake",
			ClaimValue: "disclosure",
		}
		ed, err := fakeDisclosure.EncodedDisclosure()
		assert.NoError(t, err)

		issuanceFormat, err := signer.BlindAndSign([]byte(`{"hello":{"world":"yeah"}}`), map[string]BlindOption{
			"hello": RecursiveBlindOption{},
		})
		assert.NoError(t, err)

		issuanceFormat = append(issuanceFormat, []byte("~"+ed)...)

		err = VerifyIssuance(issuanceFormat, IssuanceVerificationOptions{
			alg:       issuerSigner.ALG,
			issuerKey: issuerKey,
		})
		assert.Error(t, err)
		assert.ErrorContains(t, err, fmt.Sprintf("digest %q not found", fakeDisclosure.Digest(sha256Digest)))
	})
}
