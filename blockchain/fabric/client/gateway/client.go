package gateway

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	cfg      Config
	conn     *grpc.ClientConn
	gw       *client.Gateway
	contract *client.Contract
}

func Connect(cfg Config) (*Client, error) {
	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("gateway: read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("gateway: read key: %w", err)
	}
	tlsPEM, err := os.ReadFile(cfg.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("gateway: read tls cert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse cert: %w", err)
	}
	id, err := identity.NewX509Identity(cfg.MSPID, cert)
	if err != nil {
		return nil, fmt.Errorf("gateway: identity: %w", err)
	}
	priv, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse private key: %w", err)
	}
	sign, err := identity.NewPrivateKeySign(priv)
	if err != nil {
		return nil, fmt.Errorf("gateway: signer: %w", err)
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(tlsPEM) {
		return nil, fmt.Errorf("gateway: bad TLS CA pem")
	}
	creds := credentials.NewClientTLSFromCert(cp, cfg.PeerHostname)
	conn, err := grpc.NewClient(cfg.PeerEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("gateway: dial: %w", err)
	}
	gw, err := client.Connect(id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(cfg.EvaluateTimeout),
		client.WithEndorseTimeout(cfg.EndorseTimeout),
		client.WithSubmitTimeout(cfg.SubmitTimeout),
		client.WithCommitStatusTimeout(cfg.CommitStatusTimeout),
	)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("gateway: connect: %w", err)
	}
	return &Client{
		cfg:      cfg,
		conn:     conn,
		gw:       gw,
		contract: gw.GetNetwork(cfg.Channel).GetContract(cfg.Chaincode),
	}, nil
}

func (c *Client) Close() {
	if c.gw != nil {
		c.gw.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func (c *Client) Contract() *client.Contract { return c.contract }

func (c *Client) SubmitPhased(ctx context.Context, fn string, args ...string) (*TxResult, error) {
	res := &TxResult{Function: fn}
	t0 := time.Now()

	tBuild := time.Now()
	proposal, err := c.contract.NewProposal(fn, client.WithArguments(args...))
	if err != nil {
		return nil, fmt.Errorf("gateway: new proposal: %w", err)
	}
	res.Timing.ProposalBuildNS = time.Since(tBuild).Nanoseconds()

	tEndorse := time.Now()
	tx, err := proposal.Endorse()
	if err != nil {
		return nil, fmt.Errorf("gateway: endorse: %w", err)
	}
	res.Timing.EndorsementWaitNS = time.Since(tEndorse).Nanoseconds()
	res.TxID = tx.TransactionID()

	tSubmit := time.Now()
	commit, err := tx.Submit()
	if err != nil {
		return nil, fmt.Errorf("gateway: submit: %w", err)
	}
	res.Timing.SubmitOrderNS = time.Since(tSubmit).Nanoseconds()

	tCommit := time.Now()
	status, err := commit.Status()
	if err != nil {
		return nil, fmt.Errorf("gateway: commit status: %w", err)
	}
	res.Timing.CommitStatusWaitNS = time.Since(tCommit).Nanoseconds()
	res.Timing.TotalNS = time.Since(t0).Nanoseconds()

	if !status.Successful {
		res.Status = fmt.Sprintf("INVALID(code=%d)", status.Code)
		return res, fmt.Errorf("gateway: transaction %s rejected: code=%d", status.TransactionID, status.Code)
	}
	res.Status = "VALID"
	res.BlockNumber = status.BlockNumber
	b, err := commit.Bytes()
	if err != nil {
		return res, fmt.Errorf("gateway: commit bytes: %w", err)
	}
	res.Payload = b
	return res, nil
}

func (c *Client) EvaluatePhased(fn string, args ...string) ([]byte, int64, error) {
	t0 := time.Now()
	b, err := c.contract.EvaluateTransaction(fn, args...)
	return b, time.Since(t0).Nanoseconds(), err
}