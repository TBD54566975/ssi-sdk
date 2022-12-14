package main

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/schema"
)

// TestMain is used to set up schema caching in order to load all schemas locally
func TestMain(m *testing.M) {
	localSchemas, err := schema.GetAllLocalSchemas()
	if err != nil {
		os.Exit(1)
	}
	if _, err = schema.NewCachingLoader(localSchemas); err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestApartmentApplicationUseCase(_ *testing.T) {
	// If there is an error in main this test will fail
	main()
}
