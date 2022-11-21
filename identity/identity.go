package identity

import (
	"ccl-sdk/vault"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric/bccsp/utils"
)

// VaultIdentity represents identity using Vault Transit
type VaultIdentity struct {
	MSPID   string         `protobuf:"bytes,1,opt,name=mspid,proto3" json:"mspid,omitempty"`
	IDBytes []byte         `protobuf:"bytes,2,opt,name=idBytes,proto3" json:"idBytes,omitempty"`
	Vault   *vault.Manager `json:"-"`
	Key     *VaultKey      `json:"-"`
}

// Reset resets struct
func (m *VaultIdentity) Reset() {
	m = &VaultIdentity{}
}

// String converts struct to string reprezentation
func (m *VaultIdentity) String() string {
	return proto.CompactTextString(m)
}

// ProtoMessage indicates the identity is Protobuf serializable
func (m *VaultIdentity) ProtoMessage() {}

// Identifier returns the identifier of that identity
func (m *VaultIdentity) Identifier() *msp.IdentityIdentifier {
	return &msp.IdentityIdentifier{
		ID:    m.MSPID,
		MSPID: m.MSPID,
	}
}

// Verify a signature over some message using this identity as reference
func (m *VaultIdentity) Verify(msg []byte, sig []byte) error {
	hash := sha256.Sum256(msg)
	return m.Vault.TransitVerify(hash[:], sig, m.Key.ID, true)
}

// Serialize converts an identity to bytes
func (m *VaultIdentity) Serialize() ([]byte, error) {
	ident, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return ident, nil
}

// EnrollmentCertificate Returns the underlying ECert representing this user’s identity.
func (m *VaultIdentity) EnrollmentCertificate() []byte {
	return m.IDBytes
}

// VaultSigningIdentity represents singing identity using Vault Transit
type VaultSigningIdentity struct {
	*VaultIdentity
}

// NewVaultSigningIdentity initializes VaultSigningIdentity
func NewVaultSigningIdentity(orgName, mspid, user, cert, vaultAddress, vaultToken string) (*VaultSigningIdentity, error) {
	vaultManager, err := vault.GetManager(orgName, vaultAddress, vaultToken)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return nil, errors.New("Cannot decode cert")
	}
	pubCrt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPubKey, ok := pubCrt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid key type, expecting ECDSA Public Key")
	}
	identity := &VaultSigningIdentity{
		VaultIdentity: &VaultIdentity{
			MSPID:   mspid,
			Vault:   vaultManager,
			Key:     &VaultKey{ID: user, PubKey: ecdsaPubKey},
			IDBytes: []byte(cert),
		},
	}

	return identity, nil
}

// Sign the message
func (m *VaultSigningIdentity) Sign(msg []byte) ([]byte, error) {
	hash := sha256.Sum256(msg)
	sig, err := m.Vault.TransitSign(hash[:], m.Key.ID, true)
	if err != nil {
		return nil, err
	}

	sigLowS, err := utils.SignatureToLowS(m.Key.PubKey, sig)
	if err != nil {
		return nil, err
	}

	return sigLowS, nil
}

// PublicVersion returns the public parts of this identity
func (m *VaultSigningIdentity) PublicVersion() msp.Identity {
	return m
}

// PrivateKey returns the crypto suite representation of the private key
func (m *VaultSigningIdentity) PrivateKey() core.Key {
	return m.Key
}

// VaultKey core.Key wrapper for *ecdsa.PublicKey
type VaultKey struct {
	ID     string
	PubKey *ecdsa.PublicKey
}

// Bytes converts this key to its byte representation.
func (k *VaultKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.PubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *VaultKey) SKI() (ski []byte) {
	if k.PubKey == nil {
		return nil
	}
	raw := elliptic.Marshal(k.PubKey.Curve, k.PubKey.X, k.PubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key, false otherwise.
func (k *VaultKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key, false otherwise.
func (k *VaultKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
func (k *VaultKey) PublicKey() (core.Key, error) {
	return k, nil
}
