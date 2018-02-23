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
					Name:  "server, s",
					Usage: "Atum server `URL`",
					Value: "http://localhost:8080/",
				},
				cli.StringFlag{
					Name:  "base64-nonce, b",
					Usage: "URL base64 encoded nonce",
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
	}

	app.Run(os.Args)
}
