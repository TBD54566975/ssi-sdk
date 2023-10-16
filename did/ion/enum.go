package ion

type Network string

const (
	Mainnet Network = "mainnet"
	Testnet Network = "testnet"
)

type OperationKeyType string

const (
	Public  OperationKeyType = "public"
	Private OperationKeyType = "private"
)

type OperationType string

const (
	Create     OperationType = "create"
	Update     OperationType = "update"
	Deactivate OperationType = "deactivate"
	Recover    OperationType = "recover"
)

type Patch interface {
	GetAction() PatchAction
}

type PatchAction string

const (
	Replace          PatchAction = "replace"
	AddPublicKeys    PatchAction = "add-public-keys"
	RemovePublicKeys PatchAction = "remove-public-keys"
	AddServices      PatchAction = "add-services"
	RemoveServices   PatchAction = "remove-services"
)

func (p PatchAction) String() string {
	return string(p)
}
