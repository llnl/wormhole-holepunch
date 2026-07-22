package main

import (
	"context"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/llnl/wormhole-holepunch/internal/cmd/holepunch"
	"github.com/llnl/wormhole-holepunch/internal/version"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli.VersionPrinter = version.Printer
	app := holepunch.Tasks()

	if err := app.Run(ctx, os.Args); err != nil {
		log.Fatalln(err)
	}
}
