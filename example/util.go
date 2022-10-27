package example

import (
	"fmt"
	"os"
)

// Color coding to make it easier to read terminal
const (
	NoteColor   = "\033[1;34m%s\033[0m"
	ActionColor = "\033[1;36m%s\033[0m"
	StepColor   = "\033[1;33m%s\033[0m"
	ErrorColor  = "\033[1;31m%s\033[0m"
	DebugColor  = "\033[0;36m%s\033[0m"
	OKColor     = "\033[0;32m%s\033[0m"
)

// HandleExampleError writes an error to stderr and terminates the program
func HandleExampleError(err error, msg string) {
	if err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("%s: %v", msg, err))
		os.Exit(1) //revive:disable-line:deep-exit
	}
}

func WriteStep(s string, step int) {
	fmt.Printf(StepColor, fmt.Sprintf("Step %d: %s\n", step, s))
}

func WriteAction(s string) {
	fmt.Printf(ActionColor, fmt.Sprintf("  - %s\n", s))
}

func WriteError(s string) {
	fmt.Printf(ErrorColor, fmt.Sprintf("ERROR: %s\n", s))
}

func WriteOK(s string) {
	fmt.Printf(OKColor, fmt.Sprintf("OK: %s\n", s))
}

func WriteNote(s string) {
	fmt.Printf(NoteColor, fmt.Sprintf("      note: %s\n", s))
}
