package example

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/TBD54566975/ssi-sdk/did"
)

var (
	UnsupportedDIDErorr = errors.New("unsupported Method for DID")
	CustomWriter        = CustomStepWriter{}
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

// Resolves a DID
// Right the current implementation ssk-sdk does
// not have a universal resolver.
// https://github.com/decentralized-identity/universal-resolver
// is a case where a universal resolver is implemented,
// but the resolution would need to be hooked with the sdk.
//  TODO (andor): Should exist a universal resolution method somewhere
// in the actual SDK
func resolveDID(didStr string) (*did.DIDDocument, error) {
	split := strings.Split(string(didStr), ":")
	if len(split) < 2 {
		return nil, errors.New("invalid DID. Does not split correctly")
	}
	var method = split[1]
	switch method {
	case did.DIDKeyPrefix:
		return did.DIDKey(didStr).Expand()
	case did.DIDWebPrefix:
		return did.DIDWeb(didStr).Resolve()
	case did.PeerMethodPrefix:
		did, _, _, err := did.DIDPeer(didStr).Resolve()
		return did, err
	default:
		return nil, fmt.Errorf("%v. Got %v method", UnsupportedDIDErorr, method)
	}
}

// HandleExampleError writes an error to stderr and terminates the program
func HandleExampleError(err error, msg string) {
	if err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("%s: %v", msg, err))
		os.Exit(1)
	}
}

// Custom step writer pre-formats
// to stdout logs via steps, actions, and notes
type CustomStepWriter struct {
	step int
}

func (csw *CustomStepWriter) Write(s string) {
	fmt.Printf(StepColor, fmt.Sprintf("Step %d: %s\n", csw.step, s))
	csw.step += 1
}

func (csw *CustomStepWriter) WriteAction(s string) {
	fmt.Printf(ActionColor, fmt.Sprintf("  - %s\n", s))
}

func (csw *CustomStepWriter) WriteError(s string) {
	fmt.Printf(ErrorColor, fmt.Sprintf("ERROR: %s\n", s))
}

func (csw *CustomStepWriter) WriteOK(s string) {
	fmt.Printf(OKColor, fmt.Sprintf("OK: %s\n", s))
}

func (csw *CustomStepWriter) WriteNote(s string) {
	fmt.Printf(NoteColor, fmt.Sprintf("      note: %s\n", s))
}
