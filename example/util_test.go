package example

import "testing"

func TestUtil(_ *testing.T) {
	// If there is an error in main this test will fail
	HandleExampleError(nil, "There should be no error")
}
