package transit

import (
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/helper/keysutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	exportTypeEncryptionKey = "encryption-key"
	exportTypeSigningKey    = "signing-key"
	exportTypeHMACKey       = "hmac-key"
	exportTypeAll           = "all"
)

func (b *backend) pathExportKeys() *framework.Path {
	return &framework.Path{
		Pattern: "export/" + framework.GenericNameRegex("type") + "/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("version"),
		Fields: map[string]*framework.FieldSchema{
			"type": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Type of key to export (encryption-key, signing-key, hmac-key)",
			},
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
			"version": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Version of the key",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathPolicyExportRead,
		},

		HelpSynopsis:    pathExportHelpSyn,
		HelpDescription: pathExportHelpDesc,
	}
}

func (b *backend) pathPolicyExportRead(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	exportType := d.Get("type").(string)
	name := d.Get("name").(string)
	version := d.Get("version").(string)

	switch exportType {
	case exportTypeEncryptionKey:
	case exportTypeSigningKey:
	case exportTypeHMACKey:
	case exportTypeAll:
	default:
		return logical.ErrorResponse(fmt.Sprintf("invalid export type: %s", exportType)), logical.ErrInvalidRequest
	}

	p, lock, err := b.lm.GetPolicyShared(req.Storage, name)
	if lock != nil {
		defer lock.RUnlock()
	}
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}

	if !p.Exportable {
		return logical.ErrorResponse("key is not exportable"), nil
	}

	switch exportType {
	case exportTypeEncryptionKey:
		if !p.Type.EncryptionSupported() {
			return logical.ErrorResponse("encryption not supported for the key"), logical.ErrInvalidRequest
		}
	case exportTypeSigningKey:
		if !p.Type.SigningSupported() {
			return logical.ErrorResponse("signing not supported for the key"), logical.ErrInvalidRequest
		}
	}

	switch exportType {
	case exportTypeEncryptionKey, exportTypeSigningKey, exportTypeHMACKey:
		retKeys := map[string]string{}
		switch version {
		case "":
			for k, v := range p.Keys {
				exportKey, err := getExportKey(p, &v, exportType)
				if err != nil {
					return nil, err
				}
				retKeys[strconv.Itoa(k)] = exportKey
			}

		default:
			var versionValue int
			if version == "latest" {
				versionValue = p.LatestVersion
			} else {
				version = strings.TrimPrefix(version, "v")
				versionValue, err = strconv.Atoi(version)
				if err != nil {
					return logical.ErrorResponse("invalid key version"), logical.ErrInvalidRequest
				}
			}

			if versionValue < p.MinDecryptionVersion {
				return logical.ErrorResponse("version for export is below minimun decryption version"), logical.ErrInvalidRequest
			}
			key, ok := p.Keys[versionValue]
			if !ok {
				return logical.ErrorResponse("version does not exist or cannot be found"), logical.ErrInvalidRequest
			}

			exportKey, err := getExportKey(p, &key, exportType)
			if err != nil {
				return nil, err
			}

			retKeys[strconv.Itoa(versionValue)] = exportKey
		}
		return &logical.Response{
			Data: map[string]interface{}{
				"name": p.Name,
				"type": p.Type.String(),
				"keys": retKeys,
			},
		}, nil

	case exportTypeAll:
		policyMap, err := p.Map(nil, true)
		if err != nil {
			return nil, fmt.Errorf("failed to create policy map: %v", err)
		}
		return &logical.Response{
			Data: policyMap,
		}, nil
	}

	return nil, nil
}

func getExportKey(policy *keysutil.Policy, key *keysutil.KeyEntry, exportType string) (string, error) {
	if policy == nil {
		return "", errors.New("nil policy provided")
	}

	switch exportType {
	case exportTypeHMACKey:
		return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.HMACKey)), nil

	case exportTypeEncryptionKey:
		switch policy.Type {
		case keysutil.KeyType_AES256_GCM96:
			return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.Key)), nil

		case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA4096:
			return keysutil.EncodeRSAPrivateKey(key.RSAKey), nil
		}

	case exportTypeSigningKey:
		switch policy.Type {
		case keysutil.KeyType_ECDSA_P256:
			ecKey, err := keysutil.KeyEntryToECPrivateKey(key, elliptic.P256())
			if err != nil {
				return "", err
			}
			return ecKey, nil

		case keysutil.KeyType_ED25519:
			return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.Key)), nil

		case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA4096:
			return keysutil.EncodeRSAPrivateKey(key.RSAKey), nil
		}
	}

	return "", fmt.Errorf("unknown key type %v", policy.Type)
}

const pathExportHelpSyn = `Export named encryption or signing key`

const pathExportHelpDesc = `
This path is used to export the named keys that are configured as
exportable.
`
