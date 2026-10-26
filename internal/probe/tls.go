// Package probe collects public evidence from explicitly supplied network endpoints.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"ciphertrail/internal/inventory"
	"ciphertrail/internal/material"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// TLS performs one handshake, not exhaustive cipher or protocol enumeration.
type TLS struct {
	Address    string
	ServerName string
	Timeout    time.Duration
	ClientCert string
	ClientKey  string
	CAFile     string
	RootCAs    *x509.CertPool
	Insecure   bool
}

// Collect observes a TLS handshake without sending application requests.
func (p TLS) Collect(ctx context.Context) (inventory.Result, error) {
	var result inventory.Result
	host, err := EndpointHost(p.Address)
	if err != nil {
		return result, fmt.Errorf("TLS target must be host:port: %w", err)
	}
	if p.Timeout <= 0 {
		return result, fmt.Errorf("TLS timeout must be positive")
	}
	if (p.ClientCert == "") != (p.ClientKey == "") {
		return result, fmt.Errorf("TLS client certificate and key must be supplied together")
	}
	config := &tls.Config{
		ServerName: p.ServerName, RootCAs: p.RootCAs,
		InsecureSkipVerify: p.Insecure, // Explicit inventory option; unverified observations are labeled below.
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if config.ServerName == "" {
		config.ServerName = host
	}
	if p.CAFile != "" {
		data, err := readCredential(p.CAFile)
		if err != nil {
			return result, fmt.Errorf("read TLS CA file: %w", err)
		}
		if config.RootCAs == nil {
			config.RootCAs = x509.NewCertPool()
		} else {
			config.RootCAs = config.RootCAs.Clone()
		}
		if !config.RootCAs.AppendCertsFromPEM(data) {
			return result, fmt.Errorf("TLS CA file contains no parseable certificates")
		}
	}
	if p.ClientCert != "" {
		certData, err := readCredential(p.ClientCert)
		if err != nil {
			return result, fmt.Errorf("read TLS client certificate: %w", err)
		}
		keyData, err := readCredential(p.ClientKey)
		if err != nil {
			return result, fmt.Errorf("read TLS client key: %w", err)
		}
		certificate, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return result, fmt.Errorf("load TLS client identity: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.Address)
	if err != nil {
		return result, fmt.Errorf("connect TLS endpoint: %w", err)
	}
	defer connection.Close()
	client := tls.Client(connection, config)
	if err := client.HandshakeContext(ctx); err != nil {
		return result, fmt.Errorf("TLS handshake: %w", err)
	}
	state := client.ConnectionState()
	evidence := inventory.Evidence{
		Kind: "observed", Collector: "tls", Location: "tls://" + p.Address,
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	}
	endpoint := cdx.Component{Type: "application", Name: evidence.Location, BOMRef: inventory.Ref("tls-endpoint", p.Address, config.ServerName)}
	parent := result.Add(endpoint, evidence, "")
	result.Subjects = append(result.Subjects, parent)
	var certificates []cdx.RelatedCryptographicAsset
	for _, certificate := range state.PeerCertificates {
		ref, err := material.AddCertificate(&result, certificate, evidence, parent)
		if err != nil {
			return result, fmt.Errorf("TLS peer certificate: %w", err)
		}
		certificates = append(certificates, cdx.RelatedCryptographicAsset{Type: "certificate", Ref: ref})
	}
	component := cdx.Component{
		Type: "cryptographic-asset", Name: "TLS " + TLSVersion(state.Version),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{
				Type: cdx.CryptoProtocolTypeTLS, Version: TLSVersion(state.Version),
				CipherSuites: &[]cdx.CipherSuite{{
					Name:        tls.CipherSuiteName(state.CipherSuite),
					Identifiers: &[]string{fmt.Sprintf("0x%04x", state.CipherSuite)},
				}},
				RelatedCryptographicAssets: &certificates,
			},
		},
	}
	inventory.Property(&component, "peer-verified", strconv.FormatBool(!p.Insecure))
	inventory.Property(&component, "server-name", config.ServerName)
	inventory.Property(&component, "alpn", state.NegotiatedProtocol)
	inventory.Property(&component, "scope", "one negotiated handshake; not an enumeration of server capabilities")
	result.Add(component, evidence, parent)
	return result, nil
}

// TLSVersion formats an observed wire protocol version without silently assuming TLS 1.3.
func TLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("unknown-0x%04x", version)
	}
}
