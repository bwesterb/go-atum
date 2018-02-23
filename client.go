package atum

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// Request a timestamp for the given nonce and returns it json encoded.
//
// For more flexibility, use Stamp() or SendRequest().
func JsonStamp(serverUrl string, nonce []byte) ([]byte, Error) {
	ts, err := Stamp(serverUrl, nonce)
	if err != nil {
		return nil, err
	}
	var err2 error
	buf, err2 := json.Marshal(ts)
	if err2 != nil {
		return nil, wrapErrorf(err2, "Failed to convert timestamp to JSON")
	}
	return buf, nil
}

// Request a timestamp for the given nonce.
//
// For more flexibility, use SendRequest().
func Stamp(serverUrl string, nonce []byte) (*Timestamp, Error) {
	return SendRequest(serverUrl, Request{Nonce: nonce})
}

// Request a timestamp.
//
// For a simpler interface, use Client.Stamp() or Client.StampJson().
func SendRequest(serverUrl string, req Request) (*Timestamp, Error) {
	reqBuf, err := json.Marshal(req)
	if err != nil {
		return nil, wrapErrorf(err, "Failed to convert request to JSON")
	}

	httpResp, err := http.Post(serverUrl, "application/json", bytes.NewReader(reqBuf))
	if err != nil {
		return nil, wrapErrorf(err, "Failed POST request to %s", serverUrl)
	}
	defer httpResp.Body.Close()

	bodyBuf, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, wrapErrorf(err, "Failed to read response")
	}

	var resp Response
	err = json.Unmarshal(bodyBuf, resp)
	if err != nil {
		return nil, wrapErrorf(err, "Failed to parse response")
	}

	if resp.Error != nil {
		// TODO
		return nil, errorf("Server reported error: %s", *resp.Error)
	}

	return resp.Stamp, nil
}
