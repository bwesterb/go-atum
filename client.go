package atum

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"
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
// For a simpler interface, use Stamp() or JsonStamp().
func SendRequest(serverUrl string, req Request) (*Timestamp, Error) {
	firstTry := true
	for {
		retry, ts, err := sendRequest(serverUrl, req)
		if firstTry && retry {
			firstTry = false
			continue
		}
		return ts, err
	}
}

// Actually request the timestamp.
func sendRequest(serverUrl string, req Request) (bool, *Timestamp, Error) {
	info := cache.GetServerInfo(serverUrl)

	if info != nil {
		alg := info.DefaultSigAlg
		if req.PreferredSigAlg != nil {
			alg = *req.PreferredSigAlg
		}

		// Add proof of work, if required
		powReq, ok := info.RequiredProofOfWork[alg]
		if ok {
			if req.Time == nil {
				now := time.Now().Unix()
				req.Time = &now
			}
			pow := powReq.Fulfil(EncodeTimeNonce(*req.Time, req.Nonce))
			req.ProofOfWork = &pow
		}
	}

	reqBuf, err := json.Marshal(req)
	if err != nil {
		return false, nil, wrapErrorf(err, "Failed to convert request to JSON")
	}

	httpResp, err := http.Post(serverUrl, "application/json", bytes.NewReader(reqBuf))
	if err != nil {
		return false, nil, wrapErrorf(err, "Failed POST request to %s", serverUrl)
	}
	defer httpResp.Body.Close()

	bodyBuf, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return false, nil, wrapErrorf(err, "Failed to read response")
	}

	var resp Response
	err = json.Unmarshal(bodyBuf, &resp)
	if err != nil {
		return false, nil, wrapErrorf(err, "Failed to parse response")
	}

	if resp.Error != nil {
		switch *resp.Error {
		case ErrorMissingPow:
			fallthrough
		case ErrorPowInvalid:
			// Something went wrong with the proof of work.  Probably we're
			// missing the right nonce.
			cache.StoreServerInfo(serverUrl, *resp.Info)
			return true, nil, errorf("Server reported error: %s", *resp.Error)
		default:
			return false, nil, errorf("Server reported error: %s", *resp.Error)
		}
	}

	return false, resp.Stamp, nil
}
