package ion

import (
	"context"
	"net/http"
	"testing"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestResolver(t *testing.T) {
	t.Run("bad resolution", func(tt *testing.T) {
		emptyResolver, err := NewIONResolver(nil, "")
		assert.Error(tt, err)
		assert.Empty(tt, emptyResolver)
		assert.Contains(tt, err.Error(), "client cannot be nil")

		emptyResolver, err = NewIONResolver(http.DefaultClient, "")
		assert.Error(tt, err)
		assert.Empty(tt, emptyResolver)
		assert.Contains(tt, err.Error(), "empty url")

		resolver, err := NewIONResolver(http.DefaultClient, "badurl")
		assert.Error(tt, err)
		assert.Empty(tt, resolver)
		assert.Contains(tt, err.Error(), "invalid resolution URL")

		httpResolver, err := NewIONResolver(http.DefaultClient, "http://badurl")
		assert.Error(tt, err)
		assert.Empty(tt, httpResolver)
		assert.Contains(tt, err.Error(), "invalid resolution URL scheme; must use https")
	})

	t.Run("good resolution", func(tt *testing.T) {
		resolver, err := NewIONResolver(http.DefaultClient, "https://www.realurl.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)
	})

	t.Run("resolve an unknown DID", func(tt *testing.T) {
		gock.New("https://test-ion-resolution.com").
			Get("/bad").
			Reply(404)
		defer gock.Off()

		resolver, err := NewIONResolver(http.DefaultClient, "https://test-ion-resolution.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		result, err := resolver.Resolve(context.Background(), "bad", nil)
		assert.Error(tt, err)
		assert.Empty(tt, result)
		assert.Contains(tt, err.Error(), "could not resolve DID")
	})

	t.Run("resolve a DID with a bad response", func(tt *testing.T) {
		gock.New("https://test-ion-resolution.com").
			Get("/did:ion:test").
			Reply(200).
			BodyString("bad response")
		defer gock.Off()

		resolver, err := NewIONResolver(http.DefaultClient, "https://test-ion-resolution.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		result, err := resolver.Resolve(context.Background(), "did:ion:test", nil)
		assert.Error(tt, err)
		assert.Empty(tt, result)
		assert.Contains(tt, err.Error(), "could not parse DID Resolution Result or DID Document")
	})

	t.Run("resolve a good DID", func(tt *testing.T) {
		gock.New("https://test-ion-resolution.com").
			Get("/did:ion:test").
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:ion:test"}}`)
		defer gock.Off()

		resolver, err := NewIONResolver(http.DefaultClient, "https://test-ion-resolution.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		result, err := resolver.Resolve(context.Background(), "did:ion:test", nil)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, result)
		assert.Equal(tt, "did:ion:test", result.Document.ID)
	})

	t.Run("resolve a long form DID", func(tt *testing.T) {
		tt.Run("bad long form DID", func(ttt *testing.T) {
			gock.New("https://test-ion-resolution.com").
				Get("/did:ion:test").
				Reply(200).
				BodyString(`{"didDocument": {"id": "did:ion:test"}}`)
			defer gock.Off()

			resolver, err := NewIONResolver(http.DefaultClient, "https://test-ion-resolution.com")
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, resolver)

			badLongFormDID := "did:ion:Eia3aiRzeCkV7LOx3SERjjH93EXoIM3UoDyOQbbZAN4oWg:eyJRpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3nsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ"

			result, err := resolver.Resolve(context.Background(), badLongFormDID, nil)
			assert.Empty(ttt, result)
			assert.Error(ttt, err)
			assert.Contains(ttt, err.Error(), "invalid long form DID")
		})

		tt.Run("good long form DID", func(ttt *testing.T) {
			gock.New("https://test-ion-resolution.com").
				Get("/did:ion:test").
				Reply(200).
				BodyString(`{"didDocument": {"id": "did:ion:test"}}`)
			defer gock.Off()

			resolver, err := NewIONResolver(http.DefaultClient, "https://test-ion-resolution.com")
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, resolver)

			longFormDID := "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ"

			result, err := resolver.Resolve(context.Background(), longFormDID, nil)
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, result)
			assert.Equal(ttt, "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", result.Document.ID)
			assert.Equal(ttt, longFormDID, result.Document.AlsoKnownAs)
		})
	})

	t.Run("bad anchor", func(tt *testing.T) {
		gock.New("https://test-ion-resolution.com").
			Post("/operations").
			Reply(400)
		defer gock.Off()

		resolver, err := NewIONResolver(http.DefaultClient, "https://test-ion-resolution.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		err = resolver.Anchor(context.Background(), nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "anchor operation failed")
	})

	t.Run("good anchor", func(tt *testing.T) {
		gock.New("https://test-ion-resolution.com").
			Post("/operations").
			Reply(200)
		defer gock.Off()

		resolver, err := NewIONResolver(http.DefaultClient, "https://test-ion-resolution.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		// generate a good create op
		did, createOp, err := NewIONDID(Document{
			Services: []did.Service{
				{
					ID:              "tbd-website",
					Type:            "TBD",
					ServiceEndpoint: "https://tbd.website",
				},
			},
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, did)
		assert.NotEmpty(tt, createOp)

		err = resolver.Anchor(context.Background(), createOp)
		assert.NoError(tt, err)
	})
}

func TestRequests(t *testing.T) {
	t.Run("bad create request", func(tt *testing.T) {
		did, createOp, err := NewIONDID(Document{})
		assert.Error(tt, err)
		assert.Empty(tt, did)
		assert.Empty(tt, createOp)
		assert.Contains(tt, err.Error(), "document cannot be empty")
	})

	t.Run("good create request", func(tt *testing.T) {
		did, createOp, err := NewIONDID(Document{
			Services: []did.Service{
				{
					ID:              "tbd-service-endpoint",
					Type:            "TBDServiceEndpoint",
					ServiceEndpoint: "https://tbd.website",
				},
			},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, did)
		assert.NotEmpty(tt, createOp)

		// check DID object
		assert.NotEmpty(tt, did.ID())
		assert.Contains(tt, did.ID(), "did:ion:")
		assert.Len(tt, did.Operations(), 1)
		assert.NotEmpty(tt, did.updatePrivateKey)
		assert.NotEmpty(tt, did.recoveryPrivateKey)
		assert.NotEqual(tt, did.updatePrivateKey, did.recoveryPrivateKey)

		// try to decode long form DID
		decoded, initialState, err := DecodeLongFormDID(did.LongForm())
		assert.NoError(tt, err)
		assert.NotEmpty(tt, decoded)
		assert.NotEmpty(tt, initialState)
		assert.Equal(tt, did.ID(), decoded)

		// check create op
		assert.Equal(tt, Create, createOp.Type)
		assert.NotEmpty(tt, createOp.SuffixData)
		assert.NotEmpty(tt, createOp.Delta)
	})

	t.Run("bad update request", func(tt *testing.T) {
		did, createOp, err := NewIONDID(Document{
			Services: []did.Service{
				{
					ID:   "serviceID",
					Type: "serviceType",
				},
			},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, did)
		assert.NotEmpty(tt, createOp)

		badStateChange := StateChange{}
		updatedDID, updateOp, err := did.Update(badStateChange)
		assert.Error(tt, err)
		assert.Empty(tt, updatedDID)
		assert.Empty(tt, updateOp)
		assert.Contains(tt, err.Error(), "state change cannot be empty")
	})

	t.Run("good update request", func(tt *testing.T) {
		ionDID, createOp, err := NewIONDID(Document{
			Services: []did.Service{
				{
					ID:   "serviceID",
					Type: "serviceType",
				},
			},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ionDID)
		assert.NotEmpty(tt, createOp)

		stateChange := StateChange{
			ServicesToAdd: []did.Service{
				{
					ID:   "serviceID2",
					Type: "serviceType2",
				},
			},
		}
		updatedDID, updateOp, err := ionDID.Update(stateChange)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, updatedDID)
		assert.NotEmpty(tt, updateOp)

		// check update op
		assert.Equal(tt, Update, updateOp.Type)
		assert.NotEmpty(tt, updateOp.DIDSuffix)
		assert.Contains(tt, ionDID.ID(), updateOp.DIDSuffix)
		assert.NotEmpty(tt, updateOp.RevealValue)
		assert.NotEmpty(tt, updateOp.Delta)
		assert.NotEmpty(tt, updateOp.SignedData)

		// make sure keys are different and op is added
		assert.NotEqual(tt, ionDID.updatePrivateKey, updatedDID.updatePrivateKey)
		assert.Len(tt, ionDID.Operations(), 1)
		assert.Len(tt, updatedDID.Operations(), 2)
	})

	t.Run("bad recover request", func(tt *testing.T) {
		ionDID, createOp, err := NewIONDID(Document{
			Services: []did.Service{
				{
					ID:   "serviceID",
					Type: "serviceType",
				},
			},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ionDID)
		assert.NotEmpty(tt, createOp)

		recoveredDID, recoverOp, err := ionDID.Recover(Document{})
		assert.Error(tt, err)
		assert.Empty(tt, recoveredDID)
		assert.Empty(tt, recoverOp)
		assert.Contains(tt, err.Error(), "document cannot be empty")
	})

	t.Run("good recover request", func(tt *testing.T) {
		document := Document{
			Services: []did.Service{
				{
					ID:   "serviceID",
					Type: "serviceType",
				},
			},
		}
		did, createOp, err := NewIONDID(document)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, did)
		assert.NotEmpty(tt, createOp)

		recoveredDID, recoverOp, err := did.Recover(document)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, recoveredDID)
		assert.NotEmpty(tt, recoverOp)

		assert.Equal(tt, Recover, recoverOp.Type)
		assert.NotEmpty(tt, recoverOp.DIDSuffix)
		assert.Contains(tt, did.ID(), recoverOp.DIDSuffix)
		assert.NotEmpty(tt, recoverOp.RevealValue)
		assert.NotEmpty(tt, recoverOp.Delta)
		assert.NotEmpty(tt, recoverOp.SignedData)

		// make sure keys are different and op is added
		assert.NotEqual(tt, did.updatePrivateKey, recoveredDID.updatePrivateKey)
		assert.NotEqual(tt, did.recoveryPrivateKey, recoveredDID.recoveryPrivateKey)
		assert.Len(tt, did.Operations(), 1)
		assert.Len(tt, recoveredDID.Operations(), 2)
	})

	t.Run("bad deactivate request", func(tt *testing.T) {
		emptyDID := DID{}
		deactivatedDID, deactivateOp, err := emptyDID.Deactivate()
		assert.Error(tt, err)
		assert.Empty(tt, deactivatedDID)
		assert.Empty(tt, deactivateOp)
		assert.Contains(tt, err.Error(), "DID cannot be empty")
	})

	t.Run("good deactivate request", func(tt *testing.T) {
		document := Document{
			Services: []did.Service{
				{
					ID:   "serviceID",
					Type: "serviceType",
				},
			},
		}
		did, createOp, err := NewIONDID(document)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, did)
		assert.NotEmpty(tt, createOp)

		deactivatedDID, deactivateOp, err := did.Deactivate()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, deactivatedDID)
		assert.NotEmpty(tt, deactivateOp)

		assert.Equal(tt, Deactivate, deactivateOp.Type)
		assert.NotEmpty(tt, deactivateOp.DIDSuffix)
		assert.Contains(tt, did.ID(), deactivateOp.DIDSuffix)
		assert.NotEmpty(tt, deactivateOp.RevealValue)
		assert.NotEmpty(tt, deactivateOp.SignedData)

		assert.Len(tt, did.Operations(), 1)
		assert.Len(tt, deactivatedDID.Operations(), 2)
	})
}
