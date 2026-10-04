package controller_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ImAubrey/acore-backend/api"
	. "github.com/ImAubrey/acore-backend/service/controller"
	"github.com/ImAubrey/acore/infra/conf"
)

func TestBuildV2ray(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "ws",
		Host:              "test.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	certConfig := &CertConfig{CertMode: "none"}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildTrojan(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Trojan",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "tcp",
		Host:              "trojan.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	certConfig := &CertConfig{CertMode: "none"}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildSS(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Shadowsocks",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "tcp",
		Host:              "test.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
		CypherMethod:      "aes-128-gcm",
	}
	certConfig := &CertConfig{CertMode: "none"}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildVlessVisionWithFileTLS(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		NodeID:            1,
		Port:              443,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		EnableVless:       true,
		VlessFlow:         "xtls-rprx-vision",
	}
	config := &Config{
		CertConfig: &CertConfig{
			CertMode: "file",
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	}
	if _, err := InboundBuilder(config, nodeInfo, "test_vless_vision"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildVlessVisionRejectsPlainTCP(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		NodeID:            1,
		Port:              443,
		TransportProtocol: "tcp",
		EnableTLS:         false,
		EnableVless:       true,
		VlessFlow:         "xtls-rprx-vision",
	}
	config := &Config{CertConfig: &CertConfig{CertMode: "none"}}
	if _, err := InboundBuilder(config, nodeInfo, "test_vless_plain"); err == nil {
		t.Fatal("expected plain vless vision to be rejected")
	}
}

func TestBuildHysteria2WithFileTLS(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	nodeInfo := &api.NodeInfo{
		NodeType:          "Hy2",
		NodeID:            1,
		Port:              8443,
		TransportProtocol: "hysteria",
		EnableTLS:         true,
		HysteriaConfig: &conf.HysteriaConfig{
			Version: 2,
			Masquerade: conf.HysteriaMasqueradeConfig{
				Type: "404",
			},
		},
	}
	config := &Config{
		CertConfig: &CertConfig{
			CertMode: "file",
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	}
	if _, err := InboundBuilder(config, nodeInfo, "test_hy2"); err != nil {
		t.Fatal(err)
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "test.cert")
	keyFile := filepath.Join(dir, "test.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
