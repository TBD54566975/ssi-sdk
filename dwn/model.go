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

	// validate against json schema
	if err := IsValidDWNMessage(*msg); err != nil {
		return errors.Wrap(err, "dwn message failed json schema validation")
	}

	// validate against struct tags
	return util.NewValidator().Struct(msg)
}

// IsValidDWNMessage validates a given dwn message object against its known JSON schema
func IsValidDWNMessage(msg DWNMessage) error {
	// TODO(neal): add support for schemas https://github.com/TBD54566975/ssi-sdk/issues/62
	// jsonBytes, err := json.Marshal(msg)
	// if err != nil {
	// 	return errors.Wrap(err, "could not marshal dwn message to JSON")
	// }
	// s, err := schema.GetKnownSchema(dwnMessageSchema)
	// if err != nil {
	// 	return errors.Wrap(err, "could not get dwn message schema")
	// }
	// if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
	// 	logrus.WithError(err).Errorf("dwn message not valid against schema")
	// 	return err
	// }
	return util.NewValidator().Struct(msg)
}
