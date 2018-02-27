package main

import (
	"github.com/bwesterb/go-atum"

	"github.com/urfave/cli"

	"crypto/rand"
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
	var hashing *atum.Hashing

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

	if c.IsSet("file") {
		if req.Nonce != nil {
			return cli.NewExitError(
				"Only one of --hex-nonce, --file and --base64-nonce should be set", 7)
		}
		file, err := os.Open(c.String("file"))
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Failed to open file: %v",
				err), 8)
		}
		defer file.Close()
		hashing = &atum.Hashing{
			Hash:   atum.Shake256,
			Prefix: make([]byte, 32),
		}
		rand.Read(hashing.Prefix)
		req.Nonce, err = hashing.ComputeNonce(file)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("ComputeNonce(): %v", err), 9)
		}
	}

	if req.Nonce == nil {
		return cli.NewExitError(
			"Either --base64-nonce, --hex-nonce or --file should be set", 3)
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

	ts.Hashing = hashing

	tsBuf, err := json.Marshal(ts)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf(
			"Failed to convert timestamp to JSON: %v", err), 5)
	}

	var outFile string
	if c.IsSet("output") {
		outFile = c.String("output")
	} else if c.IsSet("file") {
		outFile = c.String("file") + ".atum-timestamp"
	} else {
		os.Stdout.Write(tsBuf)
		os.Stdout.Write([]byte{10})
		return nil
	}

	err = ioutil.WriteFile(outFile, tsBuf, 0644)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf(
			"Failed to write to %s: %v", outFile, err), 6)
	}

	return nil
}
