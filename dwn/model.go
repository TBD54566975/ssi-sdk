package dwn

import (
	"reflect"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

// DWNMessage https://identity.foundation/decentralized-web-node/spec/#messages
type DWNMessage struct {
	Data       string        `json:"data,omitempty"`
	Descriptor DWNDescriptor `json:"descriptor" validate:"required"`
}

// DWNDescriptor https://identity.foundation/decentralized-web-node/spec/#message-descriptors
type DWNDescriptor struct {
	Target    string `json:"target,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	Protocol  string `json:"protocol,omitempty"`

	// Base messages
	Nonce      string `json:"nonce" validate:"required"`
	Method     string `json:"method" validate:"required"`
	DataCID    string `json:"dataCid" validate:"required"`
	DataFormat string `json:"dataFormat" validate:"required"`

	// CollectionsQuery and CollectionsWrite
	RecordID      string `json:"recordId" validate:"required"`
	DateCreated   int64  `json:"dateCreated" validate:"required"`
	ContextID     string `json:"contextId,omitempty"`
	Schema        string `json:"schema,omitempty"`
	Published     bool   `json:"published,omitempty"`
	DatePublished int64  `json:"datePublished,omitempty"`
}

func (msg *DWNMessage) IsEmpty() bool {
	if msg == nil {
		return true
	}
	return reflect.DeepEqual(msg, &DWNMessage{})
}

func (msg *DWNMessage) IsValid() error {
	if msg.IsEmpty() {
		return errors.New("manifest is empty")
	}

	// TODO: validate the message against a json schema

	// validate against struct tags
	return util.NewValidator().Struct(msg)
}
