// Create Atum timestamps (server-side).
//
// You want to use this package if you are writing an Atum server.  If you
// just want to request an Atum timestamp, use github.com/bwesterb/go-atum.
package stamper

import (
	"github.com/bwesterb/go-atum"
	"github.com/bwesterb/go-xmssmt"

	"golang.org/x/crypto/ed25519"
)

// Create an Ed25519 timestamp
func CreateEd25519Timestamp(sk ed25519.PrivateKey, pk ed25519.PublicKey,
	time int64, nonce []byte) (ts atum.Timestamp) {
	msg := atum.EncodeTimeNonce(time, nonce)
	ts.Time = time
	ts.Sig.Alg = atum.Ed25519
	ts.Sig.Data = ed25519.Sign(sk, msg)
	ts.Sig.PublicKey = []byte(pk)
	return
}

// Create an XMSSMT timestamp
func CreateXMSSMTTimestamp(sk *xmssmt.PrivateKey, pk *xmssmt.PublicKey,
	time int64, nonce []byte) (*atum.Timestamp, error) {
	var ts atum.Timestamp
	var err error
	msg := atum.EncodeTimeNonce(time, nonce)
	ts.Time = time
	ts.Sig.Alg = atum.XMSSMT
	sig, err := sk.Sign(msg)
	if err != nil {
		return nil, err
	}
	ts.Sig.Data, err = sig.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ts.Sig.PublicKey = pkBytes
	return &ts, nil
}
