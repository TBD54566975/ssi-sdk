package issuance

import (
	"strings"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"golang.org/x/text/language"
)

type CryptographicBindingMethodSupported string

// DIDBinding returns the did.Method for this binding, and whether this is actually a DID binding method.
func (s CryptographicBindingMethodSupported) DIDBinding() (method did.Method, isDIDBinding bool) {
	methodStr, isDIDBinding := strings.CutPrefix(string(s), "did:")
	return did.Method(methodStr), isDIDBinding
}

// The possible values coming from https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10.2.3.1-2.3.1
const (
	JWKFormat CryptographicBindingMethodSupported = "jwk"
	COSEKey   CryptographicBindingMethodSupported = "cose_key"

	// AllDIDMethods is the value used to indicates support for all DID methods in the DID registry.
	AllDIDMethods CryptographicBindingMethodSupported = "did"
)

type Logo struct {
	URL     *util.URL `json:"url,omitempty"`
	AltText *string   `json:"alt_text,omitempty"`
}

type CredentialDisplay struct {
	Display

	Logo            *Logo   `json:"logo,omitempty"`
	Description     *string `json:"description,omitempty"`
	BackgroundColor *string `json:"background_color,omitempty"`
	TextColor       *string `json:"text_color,omitempty"`
}

type Format string

const (
	JWTVCJSON   Format = "jwt_vc_json"
	JWTVCJSONLD Format = "jwt_vc_json-ld"
	LDPVC       Format = "ldp_vc"
)

type CredentialSupported struct {
	Format Format `json:"format" validate:"required"`

	ID *string `json:"id,omitempty"`

	CryptographicBindingMethodsSupported []CryptographicBindingMethodSupported `json:"cryptographic_binding_methods_supported,omitempty"`

	CryptographicSuitesSupported []string `json:"cryptographic_suites_supported,omitempty"`

	Display []CredentialDisplay `json:"display,omitempty"`

	// Present when format == jwt_vc_json
	*JWTVCJSONCredentialMetadata
}

// BindingDIDMethods returns a list of all the did methods supported from the list of CryptographicBindingMethodsSupported.
func (s CredentialSupported) BindingDIDMethods() []did.Method {
	methods := make([]did.Method, 0, len(s.CryptographicBindingMethodsSupported))
	for _, bm := range s.CryptographicBindingMethodsSupported {
		method, ok := bm.DIDBinding()
		if ok {
			methods = append(methods, method)
		}
	}
	return methods
}

type Display struct {
	Name *string `json:"name,omitempty"`

	Locale *language.Tag `json:"locale,omitempty"`
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
type IssuerMetadata struct {
	CredentialIssuer util.URL `json:"credential_issuer" validate:"required"`

	// Points to a URL that resolves to authorization server metdata as defined in
	// https://www.rfc-editor.org/rfc/rfc8414.html#section-2
	AuthorizationServer *util.URL `json:"authorization_server,omitempty"`

	// Must use the `https` scheme.
	CredentialEndpoint util.URL `json:"credential_endpoint" validate:"required"`

	// Must use the `https` scheme.
	BatchCredentialEndpoint *util.URL `json:"batch_credential_endpoint,omitempty"`

	// Credentials supported indexes by the ID field.
	CredentialsSupported map[string]CredentialSupported

	// Credentials supported that did not have an ID field.
	OtherCredentialsSupported []CredentialSupported

	Display []Display `json:"display,omitempty"`
}

func (m IssuerMetadata) MarshalJSON() ([]byte, error) {
	imj := issuerMetadataJSON{
		CredentialIssuer:        m.CredentialIssuer,
		AuthorizationServer:     m.AuthorizationServer,
		CredentialEndpoint:      m.CredentialEndpoint,
		BatchCredentialEndpoint: m.BatchCredentialEndpoint,
		CredentialsSupported:    make([]CredentialSupported, 0, len(m.CredentialsSupported)+len(m.OtherCredentialsSupported)),
		Display:                 m.Display,
	}

	for _, v := range m.CredentialsSupported {
		imj.CredentialsSupported = append(imj.CredentialsSupported, v)
	}

	for _, v := range m.OtherCredentialsSupported {
		imj.CredentialsSupported = append(imj.CredentialsSupported, v)
	}

	return json.Marshal(imj)
}

func (m *IssuerMetadata) UnmarshalJSON(data []byte) error {
	var metadataJSON issuerMetadataJSON
	if err := json.Unmarshal(data, &metadataJSON); err != nil {
		return errors.Wrap(err, "unmarshalling json")
	}

	unmarshalled := IssuerMetadata{
		CredentialIssuer:          metadataJSON.CredentialIssuer,
		AuthorizationServer:       metadataJSON.AuthorizationServer,
		CredentialEndpoint:        metadataJSON.CredentialEndpoint,
		BatchCredentialEndpoint:   metadataJSON.BatchCredentialEndpoint,
		CredentialsSupported:      make(map[string]CredentialSupported, len(metadataJSON.CredentialsSupported)),
		OtherCredentialsSupported: make([]CredentialSupported, 0, len(metadataJSON.CredentialsSupported)),
		Display:                   metadataJSON.Display,
	}
	for _, c := range metadataJSON.CredentialsSupported {
		if c.ID == nil {
			unmarshalled.OtherCredentialsSupported = append(unmarshalled.OtherCredentialsSupported, c)
		} else {
			if _, ok := unmarshalled.CredentialsSupported[*c.ID]; ok {
				return errors.Errorf("found repeated credentials_supported.id for %s", *c.ID)
			}
			unmarshalled.CredentialsSupported[*c.ID] = c
		}
	}

	*m = unmarshalled

	return nil
}

type issuerMetadataJSON struct {
	CredentialIssuer util.URL `json:"credential_issuer" validate:"required"`

	// Points to a URL that resolves to authorization server metdata as defined in
	// https://www.rfc-editor.org/rfc/rfc8414.html#section-2
	AuthorizationServer *util.URL `json:"authorization_server,omitempty"`

	// Must use the `https` scheme.
	CredentialEndpoint util.URL `json:"credential_endpoint" validate:"required"`

	// Must use the `https` scheme.
	BatchCredentialEndpoint *util.URL `json:"batch_credential_endpoint,omitempty"`

	CredentialsSupported []CredentialSupported `json:"credentials_supported,omitempty"`

	Display []Display `json:"display,omitempty"`
}

func (m IssuerMetadata) IsValid() error {
	if m.CredentialEndpoint.Scheme != "https" {
		return errors.Errorf("scheme for credential_endpoint must be https (found %s)", m.CredentialEndpoint.Scheme)
	}

	if m.BatchCredentialEndpoint != nil && m.BatchCredentialEndpoint.Scheme != "https" {
		return errors.Errorf("scheme for batch_credential_endpoint must be https (found %s)", m.BatchCredentialEndpoint.Scheme)
	}

	return nil
}

type claimJSON struct {
	Mandatory *bool   `json:"mandatory,omitempty"`
	ValueType *string `json:"value_type,omitempty"`

	Display []Display `json:"display,omitempty"`
}

type Claim struct {
	Mandatory *bool
	ValueType *string

	Display       map[language.Tag]Display
	OtherDisplays []Display
}

func (c Claim) MarshalJSON() ([]byte, error) {
	jsonStruct := claimJSON{
		Mandatory: c.Mandatory,
		ValueType: c.ValueType,
		Display:   make([]Display, 0, len(c.Display)+len(c.OtherDisplays)),
	}
	for _, v := range c.Display {
		jsonStruct.Display = append(jsonStruct.Display, v)
	}
	for _, v := range c.OtherDisplays {
		jsonStruct.Display = append(jsonStruct.Display, v)
	}

	return json.Marshal(jsonStruct)
}

func (c *Claim) UnmarshalJSON(data []byte) error {
	var cJSON claimJSON
	if err := json.Unmarshal(data, &cJSON); err != nil {
		return errors.Wrap(err, "unmarshalling")
	}

	unmarshalled := Claim{
		Mandatory:     cJSON.Mandatory,
		ValueType:     cJSON.ValueType,
		Display:       make(map[language.Tag]Display, len(cJSON.Display)),
		OtherDisplays: make([]Display, 0, len(cJSON.Display)),
	}

	for _, d := range cJSON.Display {
		if d.Locale == nil {
			unmarshalled.OtherDisplays = append(unmarshalled.OtherDisplays, d)
		} else {
			if _, ok := unmarshalled.Display[*d.Locale]; ok {
				return errors.Errorf("found repeated claim.display.locale for %s", d.Locale)
			}
			unmarshalled.Display[*d.Locale] = d
		}
	}

	*c = unmarshalled

	return nil
}

type JWTVCJSONCredentialMetadata struct {
	Types             []string         `json:"types" validate:"required"`
	CredentialSubject map[string]Claim `json:"credentialSubject,omitempty"`
	Order             []string         `json:"order,omitempty"`
}
