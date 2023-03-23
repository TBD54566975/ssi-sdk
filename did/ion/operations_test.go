package ion

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestResolver(t *testing.T) {
	t.Run("bad resolver", func(tt *testing.T) {
		emptyResolver, err := NewIONResolver("")
		assert.Error(tt, err)
		assert.Empty(tt, emptyResolver)
		assert.Contains(tt, err.Error(), "empty url")

		resolver, err := NewIONResolver("badurl")
		assert.Error(tt, err)
		assert.Empty(tt, resolver)
		assert.Contains(tt, err.Error(), "invalid resolver URL")
	})

	t.Run("good resolver", func(tt *testing.T) {
		resolver, err := NewIONResolver("https://www.realurl.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)
	})

	t.Run("resolve an unknown DID", func(tt *testing.T) {
		gock.New("https://test-ion-resolver.com").
			Get("/bad").
			Reply(404)
		defer gock.Off()

		resolver, err := NewIONResolver("https://test-ion-resolver.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		result, err := resolver.Resolve("bad", nil)
		assert.Error(tt, err)
		assert.Empty(tt, result)
		assert.Contains(tt, err.Error(), "could not resolve DID")
	})

	t.Run("resolve a DID with a bad response", func(tt *testing.T) {
		gock.New("https://test-ion-resolver.com").
			Get("/did:ion:test").
			Reply(200).
			BodyString("bad response")
		defer gock.Off()

		resolver, err := NewIONResolver("https://test-ion-resolver.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		result, err := resolver.Resolve("did:ion:test", nil)
		assert.Error(tt, err)
		assert.Empty(tt, result)
		assert.Contains(tt, err.Error(), "could not parse DID Resolution Result or DID Document")
	})

	t.Run("resolve a good DID", func(tt *testing.T) {
		gock.New("https://test-ion-resolver.com").
			Get("/did:ion:test").
			Reply(200).
			BodyString(`{"id":"did:ion:test"}`)
		defer gock.Off()

		resolver, err := NewIONResolver("https://test-ion-resolver.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		result, err := resolver.Resolve("did:ion:test", nil)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, result)
		assert.Equal(tt, "did:ion:test", result.DIDDocument.ID)
	})

	t.Run("bad anchor", func(tt *testing.T) {
		gock.New("https://test-ion-resolver.com").
			Post("/operations").
			Reply(400)
		defer gock.Off()

		resolver, err := NewIONResolver("https://test-ion-resolver.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		err = resolver.Anchor(nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "anchor operation failed")
	})

	t.Run("good anchor", func(tt *testing.T) {
		gock.New("https://test-ion-resolver.com").
			Post("/operations").
			Reply(200)
		defer gock.Off()

		resolver, err := NewIONResolver("https://test-ion-resolver.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		// generate a good create op
		did, createOp, err := NewIONDID(Document{
			Services: []Service{
				{
					ID:   "serviceID",
					Type: "serviceType",
				},
			},
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, did)
		assert.NotEmpty(tt, createOp)

		err = resolver.Anchor(CreateRequest{
			Type: Create,
			SuffixData: SuffixData{
				DeltaHash:          "deltaHash",
				RecoveryCommitment: "recoveryCommitment",
			},
			Delta: Delta{
				Patches:          nil,
				UpdateCommitment: "",
			},
		})
		assert.NoError(tt, err)
	})
}

func TestRequests(t *testing.T) {
	t.Run("create request", func(tt *testing.T) {

	})

	t.Run("update request", func(tt *testing.T) {

	})

	t.Run("revoke request", func(tt *testing.T) {

	})

	t.Run("recover request", func(tt *testing.T) {

	})
}
