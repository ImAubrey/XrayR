package scenarios

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	tcpserver "github.com/ImAubrey/acore/testing/servers/tcp"
	udpserver "github.com/ImAubrey/acore/testing/servers/udp"
)

func TestAXPathVLESSOverTLS_UDPDatagram(t *testing.T) {
	if os.Getenv("ACORE_SCENARIO_TESTS") == "" {
		t.Skip("Skipping scenario tests. Set ACORE_SCENARIO_TESTS=1 to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tmpDir := t.TempDir()

	serverPort := tcpserver.PickPort()
	clientUDPPort := udpserver.PickPort()
	key := byte(0x6A)
	echoPort, closeEcho := startUDPEcho(t, key)
	defer closeEcho()

	crtPath, keyPath := writeSelfSignedCert(t, tmpDir)
	psk := "testpsk"
	userID := "b7a3e65f-2dc5-4cda-8b41-bfc4a72e3d6f"

	serverCfgPath := filepath.Join(tmpDir, "server.json")
	clientCfgPath := filepath.Join(tmpDir, "client.json")

	serverCfg := fmt.Sprintf(`{
  "log": { "loglevel": "info" },
  "inbounds": [
    {
      "tag": "in_vless_axpath_tls",
      "listen": "127.0.0.1",
      "port": %d,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": %q, "level": 0 }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "axpath",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            { "certificateFile": %q, "keyFile": %q }
          ]
        },
        "axpathSettings": { "subflows": 2, "psk": %q }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": { "redirect": "127.0.0.1:%d" }
    },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["in_vless_axpath_tls"],
        "outboundTag": "direct"
      }
    ]
  }
}`, int(serverPort), userID, filepath.ToSlash(crtPath), filepath.ToSlash(keyPath), psk, echoPort)

	clientCfg := fmt.Sprintf(`{
  "log": { "loglevel": "info" },
  "inbounds": [
    {
      "tag": "in_udp",
      "listen": "127.0.0.1",
      "port": %d,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "8.8.8.8",
        "port": 53,
        "network": "udp"
      }
    }
  ],
  "outbounds": [
    {
      "tag": "vless_axpath",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": %d,
            "users": [
              { "id": %q, "encryption": "none" }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "axpath",
        "security": "tls",
        "tlsSettings": { "serverName": "localhost", "allowInsecure": true },
        "axpathSettings": { "subflows": 2, "reconnect": true, "psk": %q }
      }
    },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["in_udp"],
        "outboundTag": "vless_axpath"
      }
    ]
  }
}`, int(clientUDPPort), int(serverPort), userID, psk)

	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientCfgPath, []byte(clientCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	serverCmd, serverOut := startAcoreWithJSON(t, serverCfgPath)
	defer stopProcess(serverCmd)
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(serverPort)), 10*time.Second); err != nil {
		t.Fatalf("server not ready: %v\n%s", err, serverOut.String())
	}

	clientCmd, clientOut := startAcoreWithJSON(t, clientCfgPath)
	defer stopProcess(clientCmd)

	payload := []byte("axpath-udp-check")
	want := xorWithKey(key, payload)

	tryExchange := func() error {
		conn, err := net.DialUDP(
			"udp",
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(clientUDPPort)},
		)
		if err != nil {
			return err
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			return err
		}

		resp := make([]byte, len(payload))
		if _, err := conn.Read(resp); err != nil {
			return err
		}
		if !bytesEqual(resp, want) {
			return fmt.Errorf("unexpected udp response got=%x want=%x", resp, want)
		}
		return nil
	}

	var lastErr error
	ok := false
	for i := 0; i < 12; i++ {
		select {
		case <-ctx.Done():
			t.Fatalf("test timeout: %v\nclient:\n%s\nserver:\n%s", ctx.Err(), clientOut.String(), serverOut.String())
		default:
		}

		if err := tryExchange(); err == nil {
			ok = true
			break
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}

	if !ok {
		t.Fatalf("axpath udp exchange failed: %v\nclient:\n%s\nserver:\n%s", lastErr, clientOut.String(), serverOut.String())
	}
}
