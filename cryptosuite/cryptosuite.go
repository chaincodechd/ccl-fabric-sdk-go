package cryptosuite

import (
	"ccl-sdk/identity"
	"ccl-sdk/vault"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"log"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric/bccsp/utils"
)

// NewVaultCryptoSuite returns cryptosuite adaptor for Signer
func NewVaultCryptoSuite(name, address, token string) core.CryptoSuite {
	vault, err := vault.GetManager(name, address, token)
	if err != nil {
		log.Fatal(err.Error())
	}
	return &VaultCryptoSuite{vault: vault, keys: make(map[string]core.Key)}
}

// VaultCryptoSuite provides a wrapper of Signer
type VaultCryptoSuite struct {
	vault *vault.Manager
	keys  map[string]core.Key
}

// KeyGen is not supported yet
func (c *VaultCryptoSuite) KeyGen(opts core.KeyGenOpts) (k core.Key, err error) {
	return nil, errors.New("Key generating is not supported")
}

// KeyImport imports new key to VaultCryptoSuite key store
func (c *VaultCryptoSuite) KeyImport(raw interface{}, opts core.KeyImportOpts) (k core.Key, err error) {
	switch raw.(type) {
	case *x509.Certificate:
		cert := raw.(*x509.Certificate)
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key type, it must be ECDSA Public Key")
		}
		pk := &identity.VaultKey{PubKey: pubKey}
		c.keys[string(string(pk.SKI()))] = pk
		return pk, nil
	case *ecdsa.PublicKey:
		pk := &identity.VaultKey{PubKey: raw.(*ecdsa.PublicKey)}
		c.keys[string(string(pk.SKI()))] = pk
		return pk, nil
	default:
		return nil, errors.New("unknown key type")
	}
}

// GetKey gets a key from VaultCryptoSuite key store
func (c *VaultCryptoSuite) GetKey(ski []byte) (k core.Key, err error) {
	key, ok := c.keys[string(ski)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// Hash returns hash og some data using VaultCryptoSuite hash
func (c *VaultCryptoSuite) Hash(msg []byte, opts core.HashOpts) (hash []byte, err error) {
	h, err := c.GetHash(opts)
	if err != nil {
		return nil, err
	}
	h.Reset()
	h.Write(msg)
	defer h.Reset()

	return h.Sum(nil), nil
}

// GetHash returns VaultCryptoSuite hash
func (c *VaultCryptoSuite) GetHash(opts core.HashOpts) (h hash.Hash, err error) {
	return sha256.New(), nil
}

// Sign uses Vault to sign the digest
func (c *VaultCryptoSuite) Sign(k core.Key, digest []byte, opts core.SignerOpts) (signature []byte, err error) {
	switch k.(type) {
	case *identity.VaultKey:
		vaultKey := k.(*identity.VaultKey)
		sig, err := c.vault.TransitSign(digest, vaultKey.ID, true)
		if err != nil {
			return nil, err
		}
		sigLowS, err := utils.SignatureToLowS(vaultKey.PubKey, sig)
		if err != nil {
			return nil, err
		}
		signature = sigLowS
		return signature, err
	default:
		return nil, errors.New("Invalid key type")
	}
}

// Verify verifies if signature is created using provided key
func (c *VaultCryptoSuite) Verify(k core.Key, signature, digest []byte, opts core.SignerOpts) (valid bool, err error) {
	switch k.(type) {
	case *identity.VaultKey:
		ecdsaPubKey := k.(*identity.VaultKey)
		r, s, err := utils.UnmarshalECDSASignature(signature)
		if err != nil {
			return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
		}
		return ecdsa.Verify(ecdsaPubKey.PubKey, digest, r, s), nil
	default:
		return false, errors.New("Invalid key type")
	}

}
