package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"cadi/internal/inventory"
	"cadi/internal/material"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/crypto/ssh"
)

// SSH obtains a host key and terminates before user authentication.
type SSH struct {
	Address string
	Timeout time.Duration
}

var hostKeyCollected = errors.New("cadi host-key collection complete")

// Collect observes an SSH host key without trusting it, authenticating, or opening channels.
func (p SSH) Collect(ctx context.Context) (inventory.Result, error) {
	var result inventory.Result
	if _, err := EndpointHost(p.Address); err != nil {
		return result, fmt.Errorf("SSH target must be host:port: %w", err)
	}
	if p.Timeout <= 0 {
		return result, fmt.Errorf("SSH timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.Address)
	if err != nil {
		return result, fmt.Errorf("connect SSH endpoint: %w", err)
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return result, fmt.Errorf("set SSH deadline: %w", err)
		}
	}
	var key ssh.PublicKey
	config := &ssh.ClientConfig{
		HostKeyCallback: func(_ string, _ net.Addr, publicKey ssh.PublicKey) error {
			key = publicKey
			return hostKeyCollected
		},
	}
	client, _, _, err := ssh.NewClientConn(connection, p.Address, config)
	if client != nil {
		client.Close()
	}
	if !errors.Is(err, hostKeyCollected) || key == nil {
		if err == nil {
			err = errors.New("SSH handshake completed without host-key interception")
		}
		return result, fmt.Errorf("collect SSH host key: %w", err)
	}
	evidence := inventory.Evidence{
		Kind: "observed", Collector: "ssh", Location: "ssh://" + p.Address,
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	}
	parent := result.Add(cdx.Component{Type: "application", Name: evidence.Location}, evidence, "")
	result.Subjects = append(result.Subjects, parent)
	keyRef, err := material.AddSSHKey(&result, key, evidence, parent, "SSH")
	if err != nil {
		return result, err
	}
	component := cdx.Component{
		Type: "cryptographic-asset", Name: "SSH 2 host-key exchange",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{
				Type: cdx.CryptoProtocolTypeSSH, Version: "2",
				RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "publicKey", Ref: keyRef}},
			},
		},
	}
	inventory.Property(&component, "peer-verified", "false")
	inventory.Property(&component, "scope", "host key only; signature and cipher negotiation are not inventoried")
	result.Add(component, evidence, parent)
	return result, nil
}
