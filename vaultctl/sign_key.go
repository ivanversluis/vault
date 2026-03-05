// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/hashicorp/cli"
	jwtauth "github.com/hashicorp/vault-plugin-auth-jwt"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
)

// defaultSSHAgentTTL is the default lifetime (in seconds) for keys added to
// the ssh-agent.
const defaultSSHAgentTTL = "3600"

// SignKeyCommand authenticates to Vault via OIDC and signs the user's SSH
// public key with Vault's SSH CA, optionally loading the result into ssh-agent.
type SignKeyCommand struct {
	UI cli.Ui
}

func (c *SignKeyCommand) Synopsis() string {
	return "Authenticate via OIDC and sign an SSH public key with Vault's SSH CA"
}

func (c *SignKeyCommand) Help() string {
	return `Usage: vaultctl sign-key [options]

  Authenticates to Vault using OIDC and then signs the user's SSH public key
  with Vault's SSH CA secrets engine. The signed certificate can optionally be
  loaded into the local ssh-agent.

Examples:

  Sign ~/.ssh/id_rsa.pub against the "developer" SSH role:

      $ vaultctl sign-key \
          -address=https://vault.example.com \
          -role=developer \
          -oidc-role=my-oidc-role

  Sign a specific key and write the certificate to a custom path:

      $ vaultctl sign-key \
          -address=https://vault.example.com \
          -role=developer \
          -public-key-path=~/.ssh/id_ed25519.pub \
          -private-key-path=~/.ssh/id_ed25519 \
          -cert-out-path=~/.ssh/id_ed25519-cert.pub

Options:

  -address          Vault server URL (or set VAULT_ADDR)
  -role             SSH CA role for signing (required)
  -mount-point      SSH secrets engine mount (default: ssh/)
  -oidc-role        OIDC auth role
  -oidc-mount       OIDC auth mount path (default: oidc)
  -public-key-path  Path to SSH public key (default: ~/.ssh/id_rsa.pub)
  -private-key-path Path to SSH private key (default: ~/.ssh/id_rsa)
  -valid-principals Comma-separated principals (default: current OS user)
  -cert-out-path    Certificate output path (default: derived from public key)
  -add-to-agent     Load key+cert into ssh-agent (default: true)
  -agent-ttl        Key lifetime in ssh-agent in seconds (default: 3600)
  -no-exec          Print signed cert to stdout instead of writing to disk
`
}

func (c *SignKeyCommand) Run(args []string) int {
	f := flag.NewFlagSet("sign-key", flag.ContinueOnError)

	var (
		flagAddress        string
		flagRole           string
		flagMountPoint     string
		flagPublicKeyPath  string
		flagPrivateKeyPath string
		flagOIDCRole       string
		flagOIDCMount      string
		flagValidPrincipals string
		flagCertOutPath    string
		flagAddToAgent     bool
		flagAgentTTL       string
		flagNoExec         bool
	)

	f.StringVar(&flagAddress, "address", "", "Vault server URL (or set VAULT_ADDR)")
	f.StringVar(&flagRole, "role", "", "SSH CA role for signing (required)")
	f.StringVar(&flagMountPoint, "mount-point", "ssh/", "SSH secrets engine mount point")
	f.StringVar(&flagPublicKeyPath, "public-key-path", "~/.ssh/id_rsa.pub", "Path to SSH public key to sign")
	f.StringVar(&flagPrivateKeyPath, "private-key-path", "~/.ssh/id_rsa", "Path to SSH private key")
	f.StringVar(&flagOIDCRole, "oidc-role", "", "OIDC auth role")
	f.StringVar(&flagOIDCMount, "oidc-mount", "oidc", "OIDC auth mount path")
	f.StringVar(&flagValidPrincipals, "valid-principals", "", "Comma-separated list of principals (default: OS username)")
	f.StringVar(&flagCertOutPath, "cert-out-path", "", "Certificate output path")
	f.BoolVar(&flagAddToAgent, "add-to-agent", true, "Load signed key into ssh-agent")
	f.StringVar(&flagAgentTTL, "agent-ttl", defaultSSHAgentTTL, "Key lifetime in ssh-agent (seconds)")
	f.BoolVar(&flagNoExec, "no-exec", false, "Print signed cert to stdout only")

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Expand ~ in paths
	flagPublicKeyPath = expandPath(flagPublicKeyPath)
	flagPrivateKeyPath = expandPath(flagPrivateKeyPath)
	if flagCertOutPath != "" {
		flagCertOutPath = expandPath(flagCertOutPath)
	}

	if flagRole == "" {
		c.UI.Error("A -role must be specified")
		return 1
	}

	// --- Step 1: Build Vault API client ---

	cfg := api.DefaultConfig()
	if flagAddress != "" {
		cfg.Address = flagAddress
	}
	// If flagAddress is empty, api.DefaultConfig() picks up VAULT_ADDR automatically.

	client, err := api.NewClient(cfg)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to create Vault client: %s", err))
		return 2
	}

	// Clear any pre-existing token so the OIDC flow is used unconditionally.
	client.SetToken("")

	// --- Step 2: OIDC authentication ---

	c.UI.Output(fmt.Sprintf("Authenticating to Vault at %s via OIDC (mount: %s, role: %q)...",
		client.Address(), flagOIDCMount, flagOIDCRole))

	oidcConfig := map[string]string{
		"mount": flagOIDCMount,
	}
	if flagOIDCRole != "" {
		oidcConfig["role"] = flagOIDCRole
	}

	handler := &jwtauth.CLIHandler{}
	secret, err := handler.Auth(client, oidcConfig)
	if err != nil {
		c.UI.Error(fmt.Sprintf("OIDC authentication failed: %s", err))
		return 2
	}
	if secret == nil || secret.Auth == nil {
		c.UI.Error("OIDC authentication returned an empty response")
		return 2
	}

	vaultToken := secret.Auth.ClientToken
	c.UI.Output("OIDC authentication successful.")

	// --- Step 3: Sign SSH public key ---

	// Create a new client with the OIDC-derived token (token is not persisted).
	signClient, err := api.NewClient(cfg)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to create authenticated client: %s", err))
		return 2
	}
	signClient.SetToken(vaultToken)

	publicKey, err := os.ReadFile(flagPublicKeyPath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to read public key %s: %s", flagPublicKeyPath, err))
		return 1
	}

	principals := flagValidPrincipals
	if principals == "" {
		principals = currentUsername()
	}

	c.UI.Output(fmt.Sprintf("Signing public key %s with SSH role %q...", flagPublicKeyPath, flagRole))

	sshClient := signClient.SSHWithMountPoint(flagMountPoint)
	signed, err := sshClient.SignKey(flagRole, map[string]interface{}{
		"public_key":       string(publicKey),
		"valid_principals": principals,
		"cert_type":        "user",
		"extensions": map[string]string{
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		},
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to sign public key: %s", err))
		return 2
	}
	if signed == nil || signed.Data == nil {
		c.UI.Error("Vault returned an empty signing response")
		return 2
	}

	signedKey, ok := signed.Data["signed_key"].(string)
	if !ok || signedKey == "" {
		c.UI.Error("Signed key is missing from the Vault response")
		return 2
	}

	// Handle -no-exec: print to stdout and exit.
	if flagNoExec {
		fmt.Print(signedKey)
		return 0
	}

	// --- Step 4: Write signed certificate to disk ---

	certPath := flagCertOutPath
	if certPath == "" {
		certPath = deriveDefaultCertPath(flagPublicKeyPath)
	}

	if err := os.WriteFile(certPath, []byte(signedKey), 0o600); err != nil {
		c.UI.Error(fmt.Sprintf("Failed to write signed certificate to %s: %s", certPath, err))
		return 2
	}
	c.UI.Output(fmt.Sprintf("Signed certificate written to %s", certPath))

	// --- Step 5: Optionally add to ssh-agent ---

	if flagAddToAgent {
		if err := addToSSHAgent(flagPrivateKeyPath, certPath, flagAgentTTL); err != nil {
			c.UI.Warn(fmt.Sprintf("Could not add key to ssh-agent: %s", err))
		} else {
			c.UI.Output("Key and certificate added to ssh-agent.")
		}
	}

	return 0
}

// deriveDefaultCertPath derives the certificate output path from a public key
// path by replacing ".pub" with "-cert.pub".
func deriveDefaultCertPath(pubKeyPath string) string {
	if strings.HasSuffix(pubKeyPath, ".pub") {
		return strings.TrimSuffix(pubKeyPath, ".pub") + "-cert.pub"
	}
	return pubKeyPath + "-cert.pub"
}

// addToSSHAgent loads the private key and signed certificate into ssh-agent.
func addToSSHAgent(privateKeyPath, certPath, agentTTL string) error {
	sshAddPath, err := exec.LookPath("ssh-add")
	if err != nil {
		return fmt.Errorf("ssh-add not found in PATH: %w", err)
	}

	expanded, err := homedir.Expand(privateKeyPath)
	if err != nil {
		expanded = privateKeyPath
	}

	cmd := exec.Command(sshAddPath, "-t", agentTTL, expanded, certPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// expandPath expands ~ to the home directory.
func expandPath(p string) string {
	expanded, err := homedir.Expand(p)
	if err != nil {
		return p
	}
	return expanded
}

// currentUsername returns the current OS username.
func currentUsername() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}
