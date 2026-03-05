# vaultctl

A standalone CLI tool that authenticates to Vault via OIDC and signs SSH public keys with Vault's SSH CA secrets engine.

## Build

```sh
# Build for current platform
make build

# Build for Linux and Windows
make build-all

# Run tests
make test
```

## Usage

```sh
vaultctl sign-key \
  -address=https://vault.example.com \
  -role=developer \
  -oidc-role=my-oidc-role
```

### Workflow

1. Opens browser for OIDC authentication
2. Signs `~/.ssh/id_rsa.pub` (or `-public-key-path`) against the named Vault SSH CA role
3. Writes signed cert to `~/.ssh/id_rsa-cert.pub` (auto-derived, or `-cert-out-path`)
4. Loads the key pair + cert into `ssh-agent` via `ssh-add` (default on, `-add-to-agent=false` to skip)

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-address` | `VAULT_ADDR` | Vault server URL |
| `-role` | *(required)* | SSH CA role for signing |
| `-oidc-role` / `-oidc-mount` | `""` / `oidc` | OIDC auth parameters |
| `-mount-point` | `ssh/` | SSH secrets engine mount point |
| `-public-key-path` | `~/.ssh/id_rsa.pub` | SSH public key to sign |
| `-private-key-path` | `~/.ssh/id_rsa` | SSH private key (for ssh-agent) |
| `-valid-principals` | OS username | Principals to embed in certificate |
| `-cert-out-path` | auto-derived | Certificate output path |
| `-add-to-agent` | `true` | Load key+cert into ssh-agent |
| `-agent-ttl` | `3600` | Key lifetime in ssh-agent (seconds) |
| `-no-exec` | `false` | Print cert to stdout instead of writing to disk |
