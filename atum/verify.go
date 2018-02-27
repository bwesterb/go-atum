package main

import (
	"github.com/bwesterb/go-atum"

	"github.com/urfave/cli"

	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func cmdVerify(c *cli.Context) error {
	var ts atum.Timestamp
	var tsBuf []byte
	var err error

	// Read timestamp
	if c.IsSet("timestamp") && c.IsSet("stdin") {
		return cli.NewExitError(
			"--timestamp and --stdin can't both be set", 11)
	}

	if c.IsSet("stdin") {
		tsBuf, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf(
				"ioutil.ReadAll(stdin): %v", err), 10)
		}
	} else if c.IsSet("timestamp") || c.IsSet("file") {
		var tsPath string
		if c.IsSet("timestamp") {
			tsPath = c.String("timestamp")
		} else {
			tsPath = c.String("file") + ".atum-timestamp"
		}
		tsBuf, err = ioutil.ReadFile(tsPath)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("ioutil.ReadFile(%s): %v",
				tsPath, err), 10)
		}
	}

	// Parse timestamp
	err = json.Unmarshal(tsBuf, &ts)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf(
			"Failed to parse timestamp file: %v", err), 11)
	}

	// Check the timestamp
	var msgReader io.Reader
	if c.IsSet("hex-nonce") {
		nonce, err := hex.DecodeString(c.String("hex-nonce"))
		if err != nil {
			return cli.NewExitError("Failed to parse --hex-nonce", 1)
		}
		msgReader = bytes.NewReader(nonce)
	}

	if c.IsSet("base64-nonce") {
		if msgReader != nil {
			return cli.NewExitError(
				"--hex-nonce and --base64-nonce shouldn't both be set", 2)
		}
		nonce, err := base64.StdEncoding.DecodeString(c.String("base64-nonce"))
		if err != nil {
			return cli.NewExitError("Failed to parse --base64-nonce", 1)
		}
		msgReader = bytes.NewReader(nonce)
	}

	if c.IsSet("file") {
		if msgReader != nil {
			return cli.NewExitError(
				"--hex-nonce, --file and --base64-nonce can't be set together", 2)
		}
		file, err := os.Open(c.String("file"))
		if err != nil {
			return cli.NewExitError(
				fmt.Sprintf("os.Open(%s): %v", c.String("file"), err), 8)
		}
		defer file.Close()
		msgReader = file
	}

	valid, err := ts.VerifyFrom(msgReader)
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("Verify: %v", err), 12)
	}

	if !valid {
		return cli.NewExitError("Invalid signature", 12)
	}

	fmt.Printf("Timestamp is valid.\n")

	return nil
}
