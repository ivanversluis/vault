// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package command

import (
	"testing"

	"github.com/hashicorp/cli"
)

func testSSHSignKeyCommand(tb testing.TB) (*cli.MockUi, *SSHSignKeyCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &SSHSignKeyCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func TestSSHSignKeyCommand_Run_MissingRole(t *testing.T) {
	t.Parallel()

	ui, cmd := testSSHSignKeyCommand(t)

	// Calling the command without -role must fail with exit code 1 and
	// print an error message – no network call should be made.
	code := cmd.Run([]string{})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if ui.ErrorWriter.String() == "" {
		t.Fatal("expected an error message when -role is missing")
	}
}

func TestDeriveDefaultCertPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "/home/user/.ssh/id_rsa.pub",
			expected: "/home/user/.ssh/id_rsa-cert.pub",
		},
		{
			input:    "/home/user/.ssh/id_ed25519.pub",
			expected: "/home/user/.ssh/id_ed25519-cert.pub",
		},
		{
			// Path without .pub suffix – cert path is appended directly.
			input:    "/home/user/.ssh/id_rsa",
			expected: "/home/user/.ssh/id_rsa-cert.pub",
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := deriveDefaultCertPath(tc.input)
			if got != tc.expected {
				t.Errorf("deriveDefaultCertPath(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestSSHSignKeyCommand_Help(t *testing.T) {
	t.Parallel()

	_, cmd := testSSHSignKeyCommand(t)
	help := cmd.Help()
	if len(help) == 0 {
		t.Fatal("expected non-empty help text")
	}
}

func TestSSHSignKeyCommand_Synopsis(t *testing.T) {
	t.Parallel()

	_, cmd := testSSHSignKeyCommand(t)
	synopsis := cmd.Synopsis()
	if len(synopsis) == 0 {
		t.Fatal("expected non-empty synopsis")
	}
}
