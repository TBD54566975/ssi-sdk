package issuance

import (
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"golang.org/x/text/language"
)

type CryptographicBindingMethodSupported string

const (
	JWKFormat CryptographicBindingMethodSupported = "jwk"
	COSEKey   CryptographicBindingMethodSupported = "cose_key"
	AllDIDs   CryptographicBindingMethodSupported = "did"
)

type Logo struct {
	URL     *util.URL `json:"url,omitempty"`
	AltText *string   `json:"alt_text,omitempty"`
}

type CredentialDisplay struct {
	displayJSON

	Logo            *Logo   `json:"logo,omitempty"`
	Description     *string `json:"description,omitempty"`
	BackgroundColor *string `json:"background_color,omitempty"`
	TextColor       *string `json:"text_color,omitempty"`
}

type Format string

const (
	JwtVcJSON   Format = "jwt_vc_json"
	JwtVcJSONLd Format = "jwt_vc_json-ld"
	LdpVc       Format = "ldp_vc"
)

type CredentialSupported struct {
	Format Format `json:"format" validate:"required"`

	Id *string `json:"id,omitempty"`

	CryptographicBindingMethodsSupported []CryptographicBindingMethodSupported `json:"cryptographic_binding_methods_supported,omitempty"`

	CryptographicSuitesSupported []string `json:"cryptographic_suites_supported,omitempty"`

	Display []CredentialDisplay `json:"display,omitempty"`

	// Present when format == jwt_vc_json
	*JWTVCJSONCredentialMetadata
}

type displayJSON struct {
	Name *string `json:"name,omitempty"`

	Locale *language.Tag `json:"locale,omitempty"`

	// TODO: Support arbitrary fields. Look at https://github.com/hyperledger/aries-framework-go/pull/564/files#diff-953974a5ec9fe3293be8ffd004be86b23666847d300650428cb21673e78fa140
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

	CredentialsSupported []CredentialSupported `json:"credentials_supported,omitempty"`

	Display []displayJSON `json:"display,omitempty"`
}

func (i IssuerMetadata) IsValid() error {
	if i.CredentialEndpoint.Scheme != "https" {
		return errors.Errorf("scheme for credential_endpoint must be https (found %s)", i.CredentialEndpoint.Scheme)
	}

	if i.BatchCredentialEndpoint != nil && i.BatchCredentialEndpoint.Scheme != "https" {
		return errors.Errorf("scheme for batch_credential_endpoint must be https (found %s)", i.BatchCredentialEndpoint.Scheme)
	}

	return nil
}

type Display struct {
	Name  *string
	Extra map[string]any
}

type claimJSON struct {
	Mandatory *bool   `json:"mandatory,omitempty"`
	ValueType *string `json:"value_type,omitempty"`

	Display []displayJSON `json:"display,omitempty"`
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
		Display:   make([]displayJSON, 0, len(c.Display)+len(c.OtherDisplays)),
	}
	for k, v := range c.Display {
		jsonStruct.Display = append(jsonStruct.Display, displayJSON{
			Name:   v.Name,
			Locale: &k,
		})
	}
	for _, v := range c.OtherDisplays {
		jsonStruct.Display = append(jsonStruct.Display, displayJSON{
			Name: v.Name,
		})
	}

	return json.Marshal(jsonStruct)
}

func (c *Claim) UnmarshalJSON(data []byte) error {
	var cJSON claimJSON
	err := json.Unmarshal(data, &cJSON)
	if err != nil {
		return errors.Wrap(err, "unmarshalling")
	}
	c.Mandatory = cJSON.Mandatory
	c.ValueType = cJSON.ValueType
	c.Display = make(map[language.Tag]Display, len(cJSON.Display))

	for _, d := range cJSON.Display {
		display := Display{
			Name: d.Name,
		}

		if d.Locale == nil {
			c.OtherDisplays = append(c.OtherDisplays, display)
		} else {
			if _, ok := c.Display[*d.Locale]; ok {
				return errors.Errorf("found repeated claim.display.locale for %s", d.Locale)
			}
			c.Display[*d.Locale] = display
		}
	}

	return nil
}

type JWTVCJSONCredentialMetadata struct {
	Types             []string         `json:"types" validate:"required"`
	CredentialSubject map[string]Claim `json:"credentialSubject,omitempty"`
	Order             []string         `json:"order,omitempty"`
}
