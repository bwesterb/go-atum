package atum

import (
	"github.com/bwesterb/go-xmssmt" // imported as xmssmt
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"

	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
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
	if !strings.HasSuffix(serverUrl, "/") {
		serverUrl += "/"
	}

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

// Computes the nonce associated to a message, when hashing is enabled.
func (h *Hashing) ComputeNonce(msg io.Reader) ([]byte, Error) {
	switch h.Hash {
	case Shake256:
		ret := make([]byte, 64)
		shake := sha3.NewShake256()
		shake.Write(h.Prefix)
		_, err := io.Copy(shake, msg)
		if err != nil {
			return nil, wrapErrorf(err, "hashing failed")
		}
		shake.Read(ret)
		return ret, nil
	default:
		return nil, errorf("Hash %s not supported", h.Hash)
	}
}

// Verifies the timestamp on a message contained in a io.Reader
func (ts *Timestamp) VerifyFrom(r io.Reader) (valid bool, err Error) {
	var nonce []byte

	// Get the nonce, by hashing possibly
	if ts.Hashing != nil {
		nonce, err = ts.Hashing.ComputeNonce(r)
		if err != nil {
			return false, err
		}
	} else {
		var err2 error
		nonce, err2 = ioutil.ReadAll(r)
		if err2 != nil {
			return false, wrapErrorf(err, "ioutil.ReadAll()")
		}
	}

	pkOk, err := ts.VerifyPublicKey()
	if err != nil || !pkOk {
		return false, err
	}

	return ts.Sig.DangerousVerifySignatureButNotPublicKey(ts.Time, nonce)
}

// Asks the Atum server if the public key on the signature should be trusted
func (ts *Timestamp) VerifyPublicKey() (trusted bool, err Error) {
	serverUrl := ts.ServerUrl
	if !strings.HasSuffix(serverUrl, "/") {
		serverUrl += "/"
	}
	expires := cache.GetPublicKey(serverUrl, ts.Sig.Alg, ts.Sig.PublicKey)
	if expires != nil && expires.Sub(time.Now()).Seconds() > 0 {
		return true, nil
	}
	q := url.Values{}
	q.Set("alg", string(ts.Sig.Alg))
	q.Set("pk", hex.EncodeToString(ts.Sig.PublicKey))
	resp, err2 := http.Get(fmt.Sprintf("%scheckPublicKey?%s",
		serverUrl, q.Encode()))
	if err2 != nil {
		return false, wrapErrorf(err2, "http.Get()")
	}
	defer resp.Body.Close()
	buf, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		return false, wrapErrorf(err2, "ioutil.ReadAll()")
	}
	var pkResp PublicKeyCheckResponse
	err2 = json.Unmarshal(buf, &pkResp)
	if err2 != nil {
		return false, wrapErrorf(err2, "json.Unmarshal()")
	}
	if pkResp.Expires.Sub(time.Unix(ts.Time, 0)).Seconds() < 0 {
		return false, errorf("Public key expired")
	}
	if !pkResp.Trusted {
		return false, nil
	}
	cache.StorePublicKey(serverUrl, ts.Sig.Alg,
		ts.Sig.PublicKey, pkResp.Expires)
	return true, nil
}

// Verifies the timestamp
func (ts *Timestamp) Verify(msgOrNonce []byte) (valid bool, err Error) {
	return ts.VerifyFrom(bytes.NewReader(msgOrNonce))
}

// Verifies the signature on a nonce, but not the public key.
//
// You should only use this function if you have checked the public key
// should be trusted.
func (sig *Signature) DangerousVerifySignatureButNotPublicKey(
	time int64, nonce []byte) (valid bool, err Error) {
	msg := EncodeTimeNonce(time, nonce)

	switch sig.Alg {
	case Ed25519:
		return ed25519.Verify(ed25519.PublicKey(sig.PublicKey),
			msg, sig.Data), nil
	case XMSSMT:
		valid, err2 := xmssmt.Verify(sig.PublicKey, sig.Data, msg)
		if err2 != nil {
			return valid, wrapErrorf(err2, "xmssmt.Verify")
		}
		return valid, nil
	default:
		return false, errorf("Signature algorithm %s not supported", sig.Alg)
	}
}
