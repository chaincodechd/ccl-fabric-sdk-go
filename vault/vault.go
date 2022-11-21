package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// Manager handles Vault operations
type Manager struct {
	client  *vault.Client
	OrgName string
}

// GetManager gets new instance of Manager
func GetManager(orgName, address, token string) (*Manager, error) {
	config := &vault.Config{Address: address}
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return &Manager{client: client, OrgName: strings.ToLower(orgName)}, nil
}

// TransitSign signs payload or SHA sum by Vault Transit engine
func (m *Manager) TransitSign(signingBytes []byte, name string, prehashed bool) ([]byte, error) {
	client := m.client.Logical()
	args := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(signingBytes),
		"prehashed": prehashed,
	}
	b64Sign, err := client.Write(fmt.Sprintf("%s_Transit/sign/%s", m.OrgName, name), args)
	if err != nil {
		return nil, err
	}
	s := strings.Split(b64Sign.Data["signature"].(string), ":")

	signature, err := base64.StdEncoding.DecodeString(s[2])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// TransitVerify verifies payload or SHA sum by Vault Transit engine
func (m *Manager) TransitVerify(signingBytes, signature []byte, name string, prehashed bool) error {
	client := m.client.Logical()
	args := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(signingBytes),
		"signature": base64.StdEncoding.EncodeToString(signature),
		"prehashed": prehashed,
	}
	b64Sign, err := client.Write(fmt.Sprintf("%s_Transit/sign/%s", m.OrgName, name), args)
	if err != nil {
		return err
	}
	valid, ok := b64Sign.Data["valid"].(bool)
	if !ok {
		return errors.New("Vault response parsing failed")
	}

	if !valid {
		return errors.New("Signature is invalid")
	}
	return nil
}
