/*
 * Copyright (c) 2018 QLC Chain Team
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	ic "github.com/libp2p/go-libp2p-crypto"
	"github.com/libp2p/go-libp2p-peer"
)

const (
	QlcConfigFile = "qlc.json"
	configVersion = 1
)

var defaultBootstrapAddresses = []string{
	"/ip4/47.244.138.61/tcp/9734/ipfs/QmdFSukPUMF3t1JxjvTo14SEEb5JV9JBT6PukGRo6A2g4f",
	"/ip4/47.75.145.146/tcp/9734/ipfs/QmW9ocg4fRjckCMQvRNYGyKxQd6GiutAY4HBRxMrGrZRfc",
}

func DefaultConfig(dir string) (*Config, error) {
	identity, err := identityConfig()
	if err != nil {
		return nil, err
	}

	var logCfg LogConfig
	_ = json.Unmarshal([]byte(`{
		"level": "info",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stderr"],
		"encoding": "json",
		"encoderConfig": {
			"messageKey": "message",
			"levelKey": "level",
			"levelEncoder": "lowercase"
		}
	}`), &logCfg)

	cfg := &Config{
		Version:             configVersion,
		DataDir:             dir,
		Mode:                "Normal",
		StorageMax:          "10GB",
		AutoGenerateReceive: false,
		LogConfig:           &logCfg,
		RPC: &RPCConfig{
			Enable: true,
			//Listen:       "/ip4/0.0.0.0/tcp/29735",
			HTTPEnabled:      true,
			HTTPEndpoint:     "tcp4://0.0.0.0:9735",
			HTTPCors:         []string{"*"},
			HttpVirtualHosts: []string{},
			WSEnabled:        true,
			WSEndpoint:       "tcp4://0.0.0.0:9736",
			IPCEnabled:       true,
			IPCEndpoint:      defaultIPCEndpoint(),
		},
		P2P: &P2PConfig{
			BootNodes:    defaultBootstrapAddresses,
			Listen:       "/ip4/0.0.0.0/tcp/9734",
			SyncInterval: 120,
		},
		Discovery: &DiscoveryConfig{
			DiscoveryInterval: 30,
			Limit:             20,
			MDNS: MDNS{
				Enabled:  true,
				Interval: 30,
			},
		},
		ID: identity,
		PerformanceTest: &PerformanceTestConfig{
			Enabled: false,
		},
	}
	return cfg, nil
}

// identityConfig initializes a new identity.
func identityConfig() (*IdentityConfig, error) {
	ident := IdentityConfig{}

	sk, pk, err := ic.GenerateKeyPair(ic.RSA, 2048)
	if err != nil {
		return &ident, err
	}

	// currently storing key unencrypted. in the future we need to encrypt it.
	// TODO(security)
	skbytes, err := sk.Bytes()
	if err != nil {
		return &ident, err
	}
	ident.PrivKey = base64.StdEncoding.EncodeToString(skbytes)

	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return &ident, err
	}
	ident.PeerID = id.Pretty()
	return &ident, nil
}

// DefaultDataDir is the default data directory to use for the databases and other persistence requirements.
func DefaultDataDir() string {
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Application Support", "GQlcchain")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "GQlcchain")
		} else {
			return filepath.Join(home, ".gqlcchain")
		}
	}
	return ""
}

func defaultIPCEndpoint() string {
	dir := filepath.Join(DefaultDataDir(), "gqlc.ipc")
	if runtime.GOOS == "windows" {
		//if strings.HasPrefix(dir, `\\.\pipe\`) {
		//	return dir
		//}
		return `\\.\pipe\gqlc.ipc`
	}
	return dir
}

func DefaultConfigFile() string {
	return filepath.Join(DefaultDataDir(), QlcConfigFile)
}

func QlcTestDataDir() string {
	return filepath.Join(DefaultDataDir(), "test")
}

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}
