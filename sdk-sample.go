package main

import (
	"ccl-sdk/cryptosuite"
	"ccl-sdk/identity"
	"fmt"
	"log"
	"os"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel/invoke"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

type Response struct {
}

func (r Response) Handle(context *invoke.RequestContext, client *invoke.ClientContext) {}

func main() {
	err := os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
	if err != nil {
		log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environment variable: %v", err)
	}

	mspid := "Org1MSP"
	orgName := "Org1"
	channelName := "mychannel"
	chaincodeName := "basic"
	fcn := "CreateAsset"
	args := [][]byte{[]byte("asset15"), []byte("red"), []byte("4"), []byte("Sahil"), []byte("1")}
	configPath := "./sdk_config.yaml"
	vaultAddress := "http://localhost:8200"
	vaultToken := ""
	userName := "user-org1.example.com"
	userCert := ``

	core := cryptosuite.NewVaultProviderFactory(orgName, vaultAddress, vaultToken)
	signingIdentity, err := identity.NewVaultSigningIdentity(orgName, mspid, userName, userCert, vaultAddress, vaultToken)
	if err != nil {
		log.Println(err.Error())
		return
	}

	sdk, err := fabsdk.New(config.FromFile(configPath), fabsdk.WithCorePkg(core))
	if err != nil {
		log.Println(err.Error())
		return
	}

	channelContext := sdk.ChannelContext(channelName, fabsdk.WithIdentity(signingIdentity), fabsdk.WithOrg(orgName))
	channelClient, err := channel.New(channelContext)
	if err != nil {
		sdk.Close()
		log.Println(err.Error())
		return
	}
	defer sdk.Close()

	ccReq := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         fcn,
		Args:        args,
	}

	response, err := channelClient.Execute(ccReq)
	if err != nil {
		log.Println("Error", err.Error())
		return
	}
	fmt.Println(response.Payload)
}
