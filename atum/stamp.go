package main

import (
	"github.com/bwesterb/go-atum"

	"github.com/urfave/cli"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"
)

func cmdStamp(c *cli.Context) {
	var req atum.Request
	var err error

	if c.IsSet("hex-nonce") {
		req.Nonce, err = hex.DecodeString(c.String("hex-nonce"))
		if err != nil {
			return cli.NewExitError("Failed to parse --hex-nonce", 1)
		}
	}

	if c.IsSet("base64-nonce") {
		if req.Nonce != nil {
			return cli.NewExitError(
				"--hex-nonce and --base64-nonce shouldn't both be set", 2)
		}
		req.Nonce, err = base64.RawURLEncoding.DecodeString(
			c.String("base64-nonce"))
		if err != nil {
			return cli.NewExitError("Failed to parse --base64-nonce", 1)
		}
	}

	if req.Nonce == nil {
		return cli.NewExitError(
			"Either --base64-nonce of --hex-nonce should be set", 3)
	}

	if c.IsSet("time") {
		req.Time = &int64(c.Int("time"))
	} else {
		req.Time = time.Now().Unix()
	}

	if c.IsSet("alg") {
		req.PreferredSigAlg = &c.String("alg")
	}

	ts, err := atum.SendRequest(c.String("server"), req)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf(
			"Failed to create timestamp: %v", err), 4)
	}

	tsBuf, err := json.Marshal(ts)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf(
			"Failed to convert timestamp to JSON: %v", err), 5)
	}
}
