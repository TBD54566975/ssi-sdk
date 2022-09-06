package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/urfave/cli/v2"
)

func main() {

	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "get",
				Aliases: []string{"c"},
				Usage:   "get an object",
				Subcommands: []*cli.Command{
					{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "get a key type",
						Subcommands: []*cli.Command{
							{
								Name:  "types",
								Usage: "get key types",
								Action: func(cCtx *cli.Context) error {
									fmt.Printf("%v\n", crypto.GetSupportedKeyTypes())
									return nil
								},
							},
						},
					},
				},
			},
			{
				Name:    "create",
				Aliases: []string{"c"},
				Usage:   "create an object",
				Subcommands: []*cli.Command{
					{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "create a did key",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "type",
								DefaultText: fmt.Sprintf("%v", crypto.Ed25519),
								Value:       fmt.Sprintf("%v", crypto.Ed25519),
								Usage:       "choose key options",
								Aliases:     []string{"t"}},
						},
						Action: func(cCtx *cli.Context) error {
							kS := cCtx.String("type")
							kt := crypto.KeyType(kS)
							if !did.IsSupportedKeyType(kt) {
								return errors.New("key type not supported")
							}
							_, did, err := did.GenerateDIDKey(kt)
							if err != nil {
								return err
							}

							fmt.Printf("Generated DID Key:\n%s\n", *did)

							return nil
						},
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

}
