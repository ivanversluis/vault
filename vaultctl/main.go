// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/cli"
)

const version = "0.1.0"

func main() {
	ui := &cli.ColoredUi{
		ErrorColor: cli.UiColorRed,
		WarnColor:  cli.UiColorYellow,
		Ui: &cli.BasicUi{
			Reader:      os.Stdin,
			Writer:      os.Stdout,
			ErrorWriter: os.Stderr,
		},
	}

	c := &cli.CLI{
		Name:    "vaultctl",
		Version: version,
		Args:    os.Args[1:],
		Commands: map[string]cli.CommandFactory{
			"sign-key": func() (cli.Command, error) {
				return &SignKeyCommand{UI: ui}, nil
			},
		},
		HelpWriter:  os.Stdout,
		ErrorWriter: os.Stderr,
	}

	exitCode, err := c.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}
