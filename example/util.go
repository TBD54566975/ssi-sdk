package example

import (
	"fmt"
	"os"
)

// HandleExampleError writes an error to stderr and terminates the program
func HandleExampleError(err error, msg string) {
	if err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("%s: %v", msg, err))
		os.Exit(1)
	}
}
