// Command carbon keeps a monorepo's secrets encrypted inside the repo.
package main

import (
	"os"

	"github.com/taylor1791/phosphorus/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
