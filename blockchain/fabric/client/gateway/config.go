package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Config struct {
	MSPID               string
	CertPath            string
	KeyPath             string
	TLSCertPath         string
	PeerEndpoint        string
	PeerHostname        string
	Channel             string
	Chaincode           string
	EvaluateTimeout     time.Duration
	EndorseTimeout      time.Duration
	SubmitTimeout       time.Duration
	CommitStatusTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		MSPID:        "Org1MSP",
		CertPath:     "fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem",
		KeyPath:      "fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk",
		TLSCertPath:  "fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
		PeerEndpoint: "localhost:7051",
		PeerHostname: "peer0.org1.example.com",
		Channel:      "mychannel",
		Chaincode:    "c5bc",

		EvaluateTimeout:     time.Minute,
		EndorseTimeout:      30 * time.Second,
		SubmitTimeout:       5 * time.Second,
		CommitStatusTimeout: time.Minute,
	}
}

type PhasedTiming struct {
	ProposalBuildNS    int64 `json:"proposal_build_ns"`
	EndorsementWaitNS  int64 `json:"endorsement_wait_ns"`
	SubmitOrderNS      int64 `json:"submit_order_ns"`
	CommitStatusWaitNS int64 `json:"commit_status_wait_ns"`
	TotalNS            int64 `json:"total_tx_latency_ns"`
}

type TxResult struct {
	Function    string       `json:"function"`
	TxID        string       `json:"tx_id"`
	Status      string       `json:"status"`
	BlockNumber uint64       `json:"block_number"`
	Payload     []byte       `json:"-"`
	Timing      PhasedTiming `json:"timing_ns"`
}

func UnavailableAsDirectMeasurement() []string {
	return []string{
		"orderer_internal_batch_timing",
		"peer_internal_commit_timing",
		"endorser_internal_execution_breakdown",
		"fabric_network_io_bytes",
	}
}

func ConfigFromTestNetwork(samplesDir, org, peerEndpoint, channel, chaincode string) (Config, error) {
	cfg := DefaultConfig()
	if org != "1" && org != "2" {
		return cfg, fmt.Errorf("gateway: unsupported org %q (want \"1\" or \"2\")", org)
	}
	base := filepath.Join(samplesDir, "test-network", "organizations",
		"peerOrganizations", "org"+org+".example.com")
	userMSP := filepath.Join(base, "users", "User1@org"+org+".example.com", "msp")

	certPath, err := firstFile(filepath.Join(userMSP, "signcerts"), ".pem")
	if err != nil {
		return cfg, fmt.Errorf("gateway: signcert: %w", err)
	}
	keyPath, err := firstFile(filepath.Join(userMSP, "keystore"), "")
	if err != nil {
		return cfg, fmt.Errorf("gateway: keystore: %w", err)
	}
	tlsPath := filepath.Join(base, "peers", "peer0.org"+org+".example.com", "tls", "ca.crt")
	if _, err := os.Stat(tlsPath); err != nil {
		return cfg, fmt.Errorf("gateway: tls ca: %w", err)
	}

	cfg.MSPID = "Org" + org + "MSP"
	cfg.CertPath = certPath
	cfg.KeyPath = keyPath
	cfg.TLSCertPath = tlsPath
	cfg.PeerEndpoint = peerEndpoint
	cfg.PeerHostname = "peer0.org" + org + ".example.com"
	if channel != "" {
		cfg.Channel = channel
	}
	if chaincode != "" {
		cfg.Chaincode = chaincode
	}
	return cfg, nil
}

func firstFile(dir, suffix string) (string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	names := []string{}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if suffix != "" && !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no file with suffix %q under %s", suffix, dir)
	}
	sort.Strings(names)
	return filepath.Join(dir, names[0]), nil
}