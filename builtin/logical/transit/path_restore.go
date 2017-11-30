package transit

import (
	"reflect"
	"time"

	"github.com/hashicorp/vault/helper/keysutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

func (b *backend) pathRestore() *framework.Path {
	return &framework.Path{
		Pattern: "restore/?$",
		Fields: map[string]*framework.FieldSchema{
			"backup": &framework.FieldSchema{
				Type:        framework.TypeMap,
				Description: "Backed up data to be restored. This should be the output of the 'backup/' endpoint",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRestoreUpdate,
		},

		HelpSynopsis:    pathRestoreHelpSyn,
		HelpDescription: pathRestoreHelpDesc,
	}
}

func (b *backend) pathRestoreUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	backup := d.Get("backup").(map[string]interface{})
	if backup == nil {
		return logical.ErrorResponse("'backup' must be supplied"), nil
	}

	// decoderHook handles the conversion of 'time.Time' and '[]byte' typed
	// fields
	decodeHook := func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		// Convert string to time.Time
		if from.Kind() == reflect.String && to == reflect.TypeOf(time.Time{}) {
			return time.Parse(time.RFC3339, data.(string))
		}
		// Convert []uint8 to []byte
		if from.Kind() == reflect.String && to == reflect.TypeOf([]byte{}) {
			return []byte(data.(string)), nil
		}
		return data, nil
	}

	var keyData keysutil.KeyData
	config := &mapstructure.DecoderConfig{
		DecodeHook: decodeHook,
		Result:     &keyData,
		// Enable weak decode to handle conversion of string indices to integer
		// within a map
		WeaklyTypedInput: true,
	}
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return nil, err
	}
	err = decoder.Decode(backup)
	if err != nil {
		return nil, err
	}

	err = b.lm.RestorePolicy(req.Storage, keyData)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

const pathRestoreHelpSyn = `Restore the named key`
const pathRestoreHelpDesc = `This path is used to restore the named key.`
