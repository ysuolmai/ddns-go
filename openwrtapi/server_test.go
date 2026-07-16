package openwrtapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
	"gopkg.in/yaml.v3"
)

func TestOpenWrtConfigRoundTripPreservesRedactedSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "ddns-go-config.yaml")
	socketPath := filepath.Join(dir, "ddns-go.sock")
	t.Setenv(util.ConfigFilePathENV, configPath)

	initial := config.Config{}
	initial.DnsConf = append(initial.DnsConf, config.DnsConfig{Name: "home"})
	initial.DnsConf[0].DNS.Name = "cloudflare"
	initial.DnsConf[0].DNS.Secret = "real-token"
	data, err := yaml.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	go func() { _ = NewServer("test-version").Serve(socketPath) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("OpenWrt API socket was not created")
		}
		time.Sleep(10 * time.Millisecond)
	}

	response, err := Call(socketPath, "config", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(response), "real-token") {
		t.Fatal("configuration response exposed a provider secret")
	}

	var public config.Config
	if err := json.Unmarshal(response, &public); err != nil {
		t.Fatal(err)
	}
	if got := public.DnsConf[0].DNS.Secret; got != redactedSecret {
		t.Fatalf("secret = %q, want redacted value", got)
	}
	public.DnsConf[0].TTL = "600"
	body, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Call(socketPath, "set-config", body); err != nil {
		t.Fatal(err)
	}

	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "real-token") {
		t.Fatal("saving a redacted configuration discarded the provider secret")
	}
	if !strings.Contains(string(saved), "600") {
		t.Fatal("configuration change was not saved")
	}
}

func TestCallRejectsUnknownOperation(t *testing.T) {
	if _, err := Call("unused", "unknown", nil); err == nil {
		t.Fatal("unknown operation was accepted")
	}
}

func TestMergeRedactedSecretsAfterDeletion(t *testing.T) {
	current := config.Config{}
	current.DnsConf = append(current.DnsConf,
		config.DnsConfig{Name: "first"},
		config.DnsConfig{Name: "second"},
	)
	current.DnsConf[0].DNS.Name = "cloudflare"
	current.DnsConf[0].DNS.Secret = "first-token"
	current.DnsConf[1].DNS.Name = "cloudflare"
	current.DnsConf[1].DNS.Secret = "second-token"

	next := config.Config{DnsConf: []config.DnsConfig{current.DnsConf[1]}}
	next.DnsConf[0].DNS.Secret = redactedSecret
	if err := mergeRedactedSecrets(&next, &current); err != nil {
		t.Fatal(err)
	}
	if got := next.DnsConf[0].DNS.Secret; got != "second-token" {
		t.Fatalf("secret = %q, want second-token", got)
	}
}

func TestMergeRejectsAmbiguousProviderAfterDeletion(t *testing.T) {
	current := config.Config{}
	current.DnsConf = append(current.DnsConf,
		config.DnsConfig{Name: "duplicate"},
		config.DnsConfig{Name: "duplicate"},
	)
	for i := range current.DnsConf {
		current.DnsConf[i].DNS.Name = "cloudflare"
		current.DnsConf[i].DNS.Secret = "token"
	}
	next := config.Config{DnsConf: []config.DnsConfig{current.DnsConf[1]}}
	next.DnsConf[0].DNS.Secret = redactedSecret
	if err := mergeRedactedSecrets(&next, &current); err == nil {
		t.Fatal("ambiguous provider identity was accepted")
	}
}
