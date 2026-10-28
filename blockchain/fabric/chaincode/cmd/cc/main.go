package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"c5full/blockchain/fabric/chaincode/contracts"
)

func main() {
	ccid := os.Getenv("CHAINCODE_ID")
	address := os.Getenv("CHAINCODE_SERVER_ADDRESS")
	vkDir := os.Getenv(contracts.EnvVKDir)

	if ccid == "" || address == "" {
		log.Panicf("cc: CHAINCODE_ID and CHAINCODE_SERVER_ADDRESS must be set (ccaas environment)")
	}

	res, err := contracts.MustInitResources(vkDir)
	if err != nil {
		log.Panicf("cc: VK initialization failed (fail-closed): %v", err)
	}
	fmt.Printf("{\"tag\":\"cc_startup\",\"profile\":%q,\"constraints\":%d,\"vk_hash\":%q,\"vk_size\":%d,\"pk_in_image\":false}\n",
		res.Manifest.ProfileID, res.Manifest.Constraints, res.VKHash, res.Manifest.SizeVK)

	c5 := &contracts.C5Contract{Res: res}
	sa := &contracts.SchemeAContract{}
	bench := &contracts.BenchmarkContract{Res: res}

	cc, err := contractapi.NewChaincode(c5, sa, bench)
	if err != nil {
		log.Panicf("cc: create chaincode: %v", err)
	}

	server := &shim.ChaincodeServer{
		CCID:     ccid,
		Address:  address,
		CC:       cc,
		TLSProps: shim.TLSProperties{Disabled: true},
	}
	if err := server.Start(); err != nil {
		log.Panicf("cc: start chaincode server: %v", err)
	}
}