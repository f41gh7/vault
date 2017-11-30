package transit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/keysutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) pathImport() *framework.Path {
	return &framework.Path{
		Pattern: "import/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"data": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Base64 encoded data to be imported. The data should be the output of the 'export/' endpoint",
			},
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathPolicyImportUpdate,
		},

		HelpSynopsis:    pathImportHelpSyn,
		HelpDescription: pathImportHelpDesc,
	}
}

func (b *backend) pathPolicyImportUpdate(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the name of the key
	name := d.Get("name").(string)

	// If a policy already exists by the given name, error out. This avoids
	// accidentally overwriting a valid key. If a named key is to be replaced,
	// it would need an explicit deletion before perfoming an import operation.
	p, lock, err := b.lm.GetPolicyShared(req.Storage, name)
	if lock != nil {
		defer lock.RUnlock()
	}
	if err != nil {
		return nil, err
	}
	if p != nil {
		return logical.ErrorResponse(fmt.Sprintf("key %q already exists", name)), nil
	}

	// Get the base64 encoded payload
	payloadB64 := d.Get("data").(string)

	// Base64 decode the payload
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to base64 decode 'data': %q", err)), nil
	}

	// Parse the payload into a map
	var payloadMap map[string]interface{}
	if err := jsonutil.DecodeJSON(payloadBytes, &payloadMap); err != nil {
		return nil, err
	}

	// For testing only.
	// TODO: Remove this
	marshaledPayloadMap, err := json.MarshalIndent(payloadMap, "", "  ")
	if err != nil {
		return nil, err
	}
	fmt.Print(string(marshaledPayloadMap))

	keyTypeRaw, ok := payloadMap["type"]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("missing %q in data", "type")), nil
	}

	keyType := keyTypeRaw.(string)
	var utilKeyType keysutil.KeyType

	switch keyType {
	case "aes256-gcm96":
		utilKeyType = keysutil.KeyType_AES256_GCM96
	case "ecdsa-p256":
		utilKeyType = keysutil.KeyType_ECDSA_P256
	case "ed25519":
		utilKeyType = keysutil.KeyType_ED25519
	case "rsa-2048":
		utilKeyType = keysutil.KeyType_RSA2048
	case "rsa-4096":
		utilKeyType = keysutil.KeyType_RSA4096
	default:
		return logical.ErrorResponse(fmt.Sprintf("unknown key type %q", keyType)), logical.ErrInvalidRequest
	}

	fmt.Printf("utilKeyType: %q\n", utilKeyType)

	derivedRaw, ok := payloadMap["derived"]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("missing %q in data", "derived")), nil
	}
	derived := derivedRaw.(bool)

	exportableRaw, ok := payloadMap["exportable"]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("missing %q in data", "exportable")), nil
	}
	exportable := exportableRaw.(bool)

	deletionAllowedRaw, ok := payloadMap["deletion_allowed"]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("missing %q in data", "deletion_allowed")), nil
	}
	deletionAllowed := deletionAllowedRaw.(bool)

	/*
		latestVersionRaw, ok := payloadMap["latest_version"]
		if !ok {
			return logical.ErrorResponse(fmt.Sprintf("missing %q in data", "latest_version")), nil
		}
		latestVersion := latestVersionRaw.(int)
	*/

	minDecryptionVersionRaw, ok := payloadMap["min_decryption_version"]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("missing %q in data", "min_decryption_version")), nil
	}
	fmt.Printf("minDecryptionVersionRaw: %#v\n", minDecryptionVersionRaw)
	minDecryptionVersion := minDecryptionVersionRaw.(int)

	minEncryptionVersionRaw, ok := payloadMap["min_encryption_version"]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("missing %q in data", "min_encryption_version")), nil
	}
	minEncryptionVersion := minEncryptionVersionRaw.(int)

	p = &keysutil.Policy{
		Name:            name,
		Type:            utilKeyType,
		Derived:         derived,
		Exportable:      exportable,
		DeletionAllowed: deletionAllowed,
		//	LatestVersion:        latestVersion,
		MinDecryptionVersion: minDecryptionVersion,
		MinEncryptionVersion: minEncryptionVersion,
	}

	fmt.Printf("policy: %#v\n", p)

	return nil, nil
}

const pathImportHelpSyn = `Import keys for a given key name.`

const pathImportHelpDesc = `
This path is used to import the exported keys under a given key name.`
