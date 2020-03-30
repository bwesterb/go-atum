package main

import (
	"os"

	"github.com/urfave/cli"
)

func main() {

	app := cli.NewApp()

	app.Commands = []cli.Command{
		{
			Name:   "stamp",
			Usage:  "Request an Atum timestamp",
			Action: cmdStamp,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "server, S",
					Usage: "Atum server `URL`",
					// Hosted by SIDN.nl
					Value: "https://keyshare.privacybydesign.foundation/atumd",
				},
				cli.StringFlag{
					Name:  "file, f",
					Usage: "Put timestamp on `FILE`",
				},
				cli.StringFlag{
					Name:  "base64-nonce, b",
					Usage: "Base64 encoded nonce",
				},
				cli.StringFlag{
					Name:  "hex-nonce, H",
					Usage: "Hex encoded nonce",
				},
				cli.IntFlag{
					Name:  "time, t",
					Usage: "UNIX time to request timestamp for",
				},
				cli.StringFlag{
					Name:  "alg, a",
					Usage: "Preferred signature algorithm (xmssmt, ed25519)",
				},
				cli.StringFlag{
					Name:  "output, o",
					Usage: "Write output to `FILE`",
				},
			},
		},
		{
			Name:   "verify",
			Usage:  "Verify an Atum timestamp",
			Action: cmdVerify,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "file, f",
					Usage: "Checks the timestamp for `FILE`",
				},
				cli.StringFlag{
					Name:  "base64-nonce, b",
					Usage: "Checks timestamp for base64 encoded nonce",
				},
				cli.StringFlag{
					Name:  "hex-nonce, H",
					Usage: "Checks timestamp for hex encoded nonce",
				},
				cli.BoolFlag{
					Name:  "stdin, s",
					Usage: "Read timestamp from stdin",
				},
				cli.StringFlag{
					Name:  "timestamp, t",
					Usage: "Read timestamp from `FILE`",
				},
				cli.StringFlag{
					Name:  "server, S",
					Usage: "Ensures the timestamp is signed by server at `URL`",
				},
				cli.BoolFlag{
					Name:  "verbose, v",
					Usage: "Show additional information on the signature",
				},
			},
		},
	}

	app.Run(os.Args)
}
