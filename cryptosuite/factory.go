package cryptosuite

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/api"
	signingMgr "github.com/hyperledger/fabric-sdk-go/pkg/fab/signingmgr"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/provider/fabpvdr"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/modlog"
)

// VaultProviderFactory represents the default SDK provider factory.
type VaultProviderFactory struct {
	address string
	token   string
	orgname string
}

// NewVaultProviderFactory returns the default SDK provider factory.
func NewVaultProviderFactory(orgName, address, token string) *VaultProviderFactory {
	return &VaultProviderFactory{orgname: orgName, address: address, token: token}
}

// CreateCryptoSuiteProvider returns a new default implementation of BCCSP
func (f *VaultProviderFactory) CreateCryptoSuiteProvider(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	cryptoSuiteProvider := NewVaultCryptoSuite(f.orgname, f.address, f.token)
	return cryptoSuiteProvider, nil
}

// CreateSigningManager returns a new default implementation of signing manager
func (f *VaultProviderFactory) CreateSigningManager(cryptoProvider core.CryptoSuite) (core.SigningManager, error) {
	return signingMgr.New(cryptoProvider)
}

// CreateInfraProvider returns a new default implementation of fabric primitives
func (f *VaultProviderFactory) CreateInfraProvider(config fab.EndpointConfig) (fab.InfraProvider, error) {
	return fabpvdr.New(config), nil
}

// NewLoggerProvider returns a new default implementation of a logger backend
// This function is separated from the factory to allow logger creation first.
func NewLoggerProvider() api.LoggerProvider {
	return modlog.LoggerProvider()
}
