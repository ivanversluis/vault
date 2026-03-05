// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package command

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/hashicorp/cli"
	credOIDC "github.com/hashicorp/vault-plugin-auth-jwt"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*SSHSignKeyCommand)(nil)
	_ cli.CommandAutocomplete = (*SSHSignKeyCommand)(nil)
)

// defaultSSHAgentTTL is the default lifetime (in seconds) for keys added to
// the ssh-agent. This avoids the signed certificate persisting in the agent
// indefinitely. Users can override this with -agent-ttl.
const defaultSSHAgentTTL = "3600"

// SSHSignKeyCommand authenticates to Vault via OIDC and then signs the user's
// SSH public key with Vault's SSH CA, optionally loading the signed certificate
// into the local ssh-agent. The Vault server address can be specified with the
// -address flag (or the VAULT_ADDR environment variable).
type SSHSignKeyCommand struct {
	*BaseCommand

	flagRole            string
	flagMountPoint      string
	flagPublicKeyPath   string
	flagPrivateKeyPath  string
	flagOIDCRole        string
	flagOIDCMount       string
	flagValidPrincipals string
	flagCertOutPath     string
	flagAddToAgent      bool
	flagAgentTTL        string
	flagNoExec          bool
}

func (c *SSHSignKeyCommand) Synopsis() string {
	return "Sign an SSH key via Vault after OIDC authentication"
}

func (c *SSHSignKeyCommand) Help() string {
	helpText := `
Usage: vault ssh sign-key [options]

  Authenticates to Vault using OIDC and then signs the user's SSH public key
  with Vault's SSH CA secrets engine. The signed certificate can optionally be
  loaded into the local ssh-agent so subsequent SSH connections use it
  automatically.

  The Vault server address can be provided with the -address flag or the
  VAULT_ADDR environment variable.

  Sign ~/.ssh/id_rsa.pub against the "developer" SSH role using OIDC:

      $ vault ssh sign-key \
          -address=https://vault.example.com \
          -role=developer \
          -oidc-role=my-oidc-role

  Sign a specific key and write the certificate to a custom path:

      $ vault ssh sign-key \
          -address=https://vault.example.com \
          -role=developer \
          -public-key-path=~/.ssh/id_ed25519.pub \
          -private-key-path=~/.ssh/id_ed25519 \
          -cert-out-path=~/.ssh/id_ed25519-cert.pub

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *SSHSignKeyCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)

	f := set.NewFlagSet("SSH Sign-Key Options")

	f.StringVar(&StringVar{
		Name:       "role",
		Target:     &c.flagRole,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage:      "Name of the Vault SSH role to use when signing the public key.",
	})

	f.StringVar(&StringVar{
		Name:       "mount-point",
		Target:     &c.flagMountPoint,
		Default:    "ssh/",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage:      "Mount point of the Vault SSH secrets engine.",
	})

	f.StringVar(&StringVar{
		Name:       "public-key-path",
		Target:     &c.flagPublicKeyPath,
		Default:    "~/.ssh/id_rsa.pub",
		EnvVar:     "",
		Completion: complete.PredictFiles("*"),
		Usage:      "Path to the SSH public key to sign.",
	})

	f.StringVar(&StringVar{
		Name:       "private-key-path",
		Target:     &c.flagPrivateKeyPath,
		Default:    "~/.ssh/id_rsa",
		EnvVar:     "",
		Completion: complete.PredictFiles("*"),
		Usage: "Path to the SSH private key that corresponds to -public-key-path. " +
			"Used when loading the signed certificate into ssh-agent.",
	})

	f.StringVar(&StringVar{
		Name:       "oidc-role",
		Target:     &c.flagOIDCRole,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage:      "Vault OIDC role to use for authentication. Passed as the \"role\" parameter to the OIDC auth method.",
	})

	f.StringVar(&StringVar{
		Name:       "oidc-mount",
		Target:     &c.flagOIDCMount,
		Default:    "oidc",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage:      "Mount path of the OIDC auth method in Vault.",
	})

	f.StringVar(&StringVar{
		Name:       "valid-principals",
		Target:     &c.flagValidPrincipals,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage: "Comma-separated list of valid principals to embed in the signed " +
			"certificate. Defaults to the current OS username.",
	})

	f.StringVar(&StringVar{
		Name:       "cert-out-path",
		Target:     &c.flagCertOutPath,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictFiles("*"),
		Usage: "Path where the signed certificate will be written. Defaults to " +
			"the public-key-path with the \".pub\" extension replaced by \"-cert.pub\".",
	})

	f.BoolVar(&BoolVar{
		Name:    "add-to-agent",
		Target:  &c.flagAddToAgent,
		Default: true,
		Usage: "Automatically add the private key and signed certificate to the " +
			"local ssh-agent after signing.",
	})

	f.StringVar(&StringVar{
		Name:    "agent-ttl",
		Target:  &c.flagAgentTTL,
		Default: defaultSSHAgentTTL,
		EnvVar:  "",
		Usage: "Lifetime in seconds for the key in the ssh-agent. " +
			"When the TTL expires the agent will remove the key automatically. " +
			"Default: " + defaultSSHAgentTTL + " seconds (1 hour).",
	})

	f.BoolVar(&BoolVar{
		Name:    "no-exec",
		Target:  &c.flagNoExec,
		Default: false,
		Usage: "Print the signed certificate to stdout rather than writing it to " +
			"disk or loading it into ssh-agent.",
	})

	return set
}

func (c *SSHSignKeyCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *SSHSignKeyCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *SSHSignKeyCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Expand ~ in paths.
	c.flagPublicKeyPath = expandPath(c.flagPublicKeyPath)
	c.flagPrivateKeyPath = expandPath(c.flagPrivateKeyPath)
	if c.flagCertOutPath != "" {
		c.flagCertOutPath = expandPath(c.flagCertOutPath)
	}

	if c.flagRole == "" {
		c.UI.Error("A -role must be specified")
		return 1
	}

	// --- Step 1: OIDC authentication ---

	// Build a Vault client using the address provided via -address / VAULT_ADDR.
	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	// Clear any pre-existing token so that the OIDC flow is used unconditionally.
	client.SetToken("")

	c.UI.Output(fmt.Sprintf("Authenticating to Vault at %s via OIDC (mount: %s, role: %q)...",
		client.Address(), c.flagOIDCMount, c.flagOIDCRole))

	oidcConfig := map[string]string{
		"mount": c.flagOIDCMount,
	}
	if c.flagOIDCRole != "" {
		oidcConfig["role"] = c.flagOIDCRole
	}

	handler := &credOIDC.CLIHandler{}
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

	// --- Step 2: Sign SSH public key ---

	// Use a fresh client with the OIDC-derived token so the sign request is
	// authorised, without persisting the token to the token helper.
	signClient, err := c.newClientWithToken(client, vaultToken)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to create authenticated client: %s", err))
		return 2
	}

	publicKey, err := os.ReadFile(c.flagPublicKeyPath)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to read public key %s: %s", c.flagPublicKeyPath, err))
		return 1
	}

	principals := c.flagValidPrincipals
	if principals == "" {
		principals = currentUsername()
	}

	c.UI.Output(fmt.Sprintf("Signing public key %s with Vault SSH role %q...", c.flagPublicKeyPath, c.flagRole))

	sshClient := signClient.SSHWithMountPoint(c.flagMountPoint)
	signed, err := sshClient.SignKey(c.flagRole, map[string]interface{}{
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
	if c.flagNoExec {
		if c.flagField != "" {
			return PrintRawField(c.UI, signed, c.flagField)
		}
		return OutputSecret(c.UI, signed)
	}

	// --- Step 3: Write signed certificate to disk ---

	certPath := c.flagCertOutPath
	if certPath == "" {
		certPath = deriveDefaultCertPath(c.flagPublicKeyPath)
	}

	if err := os.WriteFile(certPath, []byte(signedKey), 0o600); err != nil {
		c.UI.Error(fmt.Sprintf("Failed to write signed certificate to %s: %s", certPath, err))
		return 2
	}
	c.UI.Output(fmt.Sprintf("Signed certificate written to %s", certPath))

	// --- Step 4: Optionally add to ssh-agent ---

	if c.flagAddToAgent {
		if err := addToSSHAgent(c.flagPrivateKeyPath, certPath, c.flagAgentTTL); err != nil {
			c.UI.Warn(fmt.Sprintf("Could not add key to ssh-agent: %s", err))
		} else {
			c.UI.Output(fmt.Sprintf("Key and certificate added to ssh-agent."))
		}
	}

	return 0
}

// newClientWithToken creates a copy of the provided client configured with the
// given Vault token. The address and TLS settings are preserved.
func (c *SSHSignKeyCommand) newClientWithToken(base *api.Client, token string) (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = base.Address()

	newClient, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	newClient.SetToken(token)

	return newClient, nil
}

// deriveDefaultCertPath derives the default certificate output path from a
// public key path by replacing the ".pub" suffix with "-cert.pub". When the
// path does not end in ".pub" the suffix "-cert.pub" is appended directly.
func deriveDefaultCertPath(pubKeyPath string) string {
	if strings.HasSuffix(pubKeyPath, ".pub") {
		base := strings.TrimSuffix(pubKeyPath, ".pub")
		return base + "-cert.pub"
	}
	return pubKeyPath + "-cert.pub"
}

// addToSSHAgent calls ssh-add with the private key and signed certificate so
// that they are available to the local ssh-agent.
func addToSSHAgent(privateKeyPath, certPath, agentTTL string) error {
	// ssh-add accepts the private key path and automatically picks up the
	// corresponding certificate when it is located next to the key.
	// Passing the cert path explicitly ensures the right certificate is used
	// even when the default naming convention is not followed.
	sshAddPath, err := exec.LookPath("ssh-add")
	if err != nil {
		return fmt.Errorf("ssh-add not found in PATH: %w", err)
	}

	// Expand the private key path in case it contains a tilde.
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

// currentUsername returns the current OS username, falling back to "unknown"
// if it cannot be determined.
func currentUsername() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}
