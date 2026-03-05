// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/hashicorp/cli"
)

func testSignKeyCommand(tb testing.TB) (*cli.MockUi, *SignKeyCommand) {
	tb.Helper()
	ui := cli.NewMockUi()
	return ui, &SignKeyCommand{UI: ui}
}

func Test_SignKeyCommand_Run_MissingRole(t *testing.T) {
	t.Parallel()

	ui, cmd := testSignKeyCommand(t)

	code := cmd.Run([]string{})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if ui.ErrorWriter.String() == "" {
		t.Fatal("expected an error message when -role is missing")
	}
}

func Test_deriveDefaultCertPath(t *testing.T) {
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

func Test_SignKeyCommand_Help(t *testing.T) {
	t.Parallel()

	_, cmd := testSignKeyCommand(t)
	help := cmd.Help()
	if len(help) == 0 {
		t.Fatal("expected non-empty help text")
	}
}

func Test_SignKeyCommand_Synopsis(t *testing.T) {
	t.Parallel()

	_, cmd := testSignKeyCommand(t)
	synopsis := cmd.Synopsis()
	if len(synopsis) == 0 {
		t.Fatal("expected non-empty synopsis")
	}
}
