// Command yunmen is the Yunmen CLI client.
package main

import (
	"os"

	"github.com/txchen/yunmen/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
