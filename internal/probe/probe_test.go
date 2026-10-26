package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/testutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/crypto/ssh"
)

func assertEndpointSubject(t *testing.T, result inventory.Result, name string) {
	t.Helper()
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if len(result.Subjects) != 1 || bom.Metadata.Component == nil ||
		bom.Metadata.Component.BOMRef != result.Subjects[0] || bom.Metadata.Component.Type != cdx.ComponentTypeApplication ||
		bom.Metadata.Component.Name != name {
		t.Fatal("observed endpoint lost its primary component identity")
	}
}

func TestTLSAndMTLS(t *testing.T) {
	for _, mutual := range []bool{false, true} {
		t.Run(map[bool]string{false: "tls", true: "mtls"}[mutual], func(t *testing.T) {
			identity, certificate, certPEM, keyPEM := testutil.Identity(t)
			roots := x509.NewCertPool()
			roots.AddCert(certificate)
			config := &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS13}
			if mutual {
				config.ClientAuth, config.ClientCAs = tls.RequireAndVerifyClientCert, roots
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			done := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err == nil {
					defer connection.Close()
					err = connection.(*tls.Conn).Handshake()
				}
				done <- err
			}()
			collector := TLS{Address: listener.Addr().String(), Timeout: 2 * time.Second, RootCAs: roots}
			if mutual {
				dir := t.TempDir()
				collector.ClientCert, collector.ClientKey = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
				if err := os.WriteFile(collector.ClientCert, certPEM, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(collector.ClientKey, keyPEM, 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := collector.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			assertEndpointSubject(t, result, "tls://"+collector.Address)
			found := false
			for _, entry := range result.Entries {
				if p := entry.Component.CryptoProperties; p != nil && p.ProtocolProperties != nil {
					found = p.ProtocolProperties.Version == "1.3" && len(*p.ProtocolProperties.CipherSuites) == 1 && entry.Evidence.Kind == "observed"
					if p.ProtocolProperties.CryptoRefArray != nil || p.ProtocolProperties.RelatedCryptographicAssets == nil ||
						len(*p.ProtocolProperties.RelatedCryptographicAssets) == 0 {
						t.Fatal("TLS certificate relationships did not migrate to 1.7")
					}
				}
			}
			if !found {
				t.Fatal("missing negotiated TLS properties")
			}
		})
	}
}

func TestTLSHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			buffer := make([]byte, 4096)
			for {
				if _, err := connection.Read(buffer); err != nil {
					return
				}
			}
		}
	}()
	start := time.Now()
	_, err = (TLS{Address: listener.Addr().String(), Timeout: 100 * time.Millisecond}).Collect(context.Background())
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("timeout not enforced: %v", err)
	}
	<-done
}

func TestSSHStopsBeforeAuthentication(t *testing.T) {
	identity, _, _, _ := testutil.Identity(t)
	signer, err := ssh.NewSignerFromKey(identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	var authentications atomic.Int32
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, errors.New("not allowed")
		},
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { authentications.Add(1) },
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			_, _, _, _ = ssh.NewServerConn(connection, config)
		}
	}()
	result, err := (SSH{Address: listener.Addr().String(), Timeout: time.Second}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if authentications.Load() != 0 {
		t.Fatal("SSH probe attempted user authentication")
	}
	assertEndpointSubject(t, result, "ssh://"+listener.Addr().String())
	found := false
	for _, entry := range result.Entries {
		if p := entry.Component.CryptoProperties; p != nil && p.RelatedCryptoMaterialProperties != nil {
			found = p.RelatedCryptoMaterialProperties.Type == "public-key" && entry.Evidence.Kind == "observed"
		}
		if p := entry.Component.CryptoProperties; p != nil && p.ProtocolProperties != nil {
			if p.ProtocolProperties.CryptoRefArray != nil || p.ProtocolProperties.RelatedCryptographicAssets == nil ||
				len(*p.ProtocolProperties.RelatedCryptographicAssets) != 1 {
				t.Fatal("SSH host-key relationship did not migrate to 1.7")
			}
		}
	}
	if !found {
		t.Fatal("no host key observed")
	}
}
