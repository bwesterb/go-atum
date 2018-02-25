package main

import (
	"github.com/bwesterb/go-atum"

	"github.com/urfave/cli"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

func cmdStamp(c *cli.Context) error {
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
		req.Nonce, err = base64.StdEncoding.DecodeString(
			c.String("base64-nonce"))
		if err != nil {
			return cli.NewExitError("Failed to parse --base64-nonce", 1)
		}
	}

	if req.Nonce == nil {
		return cli.NewExitError(
			"Either --base64-nonce of --hex-nonce should be set", 3)
	}

	var theTime int64
	if c.IsSet("time") {
		theTime = int64(c.Int("time"))
	} else {
		theTime = time.Now().Unix()
	}
	req.Time = &theTime

	if c.IsSet("alg") {
		var preferredAlg = atum.SignatureAlgorithm(c.String("alg"))
		req.PreferredSigAlg = &preferredAlg
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

	if !c.IsSet("output") {
		os.Stdout.Write(tsBuf)
		return nil
	}

	err = ioutil.WriteFile(c.String("output"), tsBuf, 0644)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf(
			"Failed to write to %s: %v", c.String("output"), err), 6)
	}

	return nil
}
