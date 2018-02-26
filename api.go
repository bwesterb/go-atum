// Atum is a post-quantum secure easy-to-use trusted time-stamping protocol.
package atum

import (
	"github.com/bwesterb/go-pow"

	"encoding/binary"
	"time"
)

// A signed timestamp on a nonce or longer message.
//
// The message/nonce are not included.
type Timestamp struct {

	// The unix time at which the timestamp was set
	Time int64

	// The server by which the timestamp was set
	ServerUrl string

	// The signature.
	Sig Signature

	// The Atum server only signs short nonces.  To timestamp a longer message,
	// the Atum server first hashes the long message to a nonce, which
	// in turn is signed by the Atum server.  If this is the case, the following
	// field contains the hash used.
	Hashing *Hashing `json:",omitempty"`
}

// See the Timestamp.Hashing field
type Hashing struct {

	// The hash function used to compress the message into a nonce
	Hash Hash

	// A prefix to hide the hash of the message from the Atum server
	Prefix []byte
}

// A possible hash
type Hash string

const (
	Shake256 Hash = "shake256"
)

// The signature of the timestamp
type Signature struct {

	// The signature algorithm used
	Alg SignatureAlgorithm

	// The serialized signature
	Data []byte

	// The serialized public key with which the signature was set
	PublicKey []byte
}

// A request to put a timestamp on a nonce.
type Request struct {

	// The nonce to timestamp.  The server might reject the timestamp if it
	// is too long.  See ServerInfo.MaxNonceSize.
	Nonce []byte

	// The proof of work (if required).
	//
	// THe SendRequest() function will fill this field if it is required by
	// ServerInfo.RequiredProofOfWork.
	ProofOfWork *pow.Proof

	// The following fields are optional.

	// Unix time to put on the timestamp.  The server will reject the request
	// if this time is too far of its own time.  See ServerInfo.AcceptableLag.
	Time *int64

	// Preferred signature algorithm.  If the specified signature algorithm
	// is not supported or this field is omitted, the server will revert
	// to the default.
	PreferredSigAlg *SignatureAlgorithm
}

// The response of the Atum server to a request
type Response struct {
	// Error
	Error *ErrorCode

	// The timestamp
	Stamp *Timestamp

	// In case of most errors, the server will include server information.
	Info *ServerInfo
}

// Response of the Atum server to a public key check
type PublicKeyCheckResponse struct {
	// Should we trust this public key
	Trusted bool

	// When should you check again?
	Expires time.Time
}

type ErrorCode string

const (
	// There is too much lag between the time requested for the timestamp
	// and the time at which the request is processed.
	ErrorCodeLag ErrorCode = "too much lag"

	ErrorMissingNonce ErrorCode = "missing nonce"
	ErrorNonceTooLong ErrorCode = "nonce is too long"
	ErrorMissingPow   ErrorCode = "proof of work is missing"
	ErrorPowInvalid   ErrorCode = "proof of work is invalid"
)

// Supported signature algorithms.
type SignatureAlgorithm string

const (
	// Ed25519 EdDSA signatures. See rfc8032
	Ed25519 SignatureAlgorithm = "ed25519"

	// XMSS[MT] signatures.
	// See https://tools.ietf.org/html/draft-irtf-cfrg-xmss-hash-based-signatures-11
	XMSSMT = "xmssmt"
)

// Information published by an Atum server.
type ServerInfo struct {
	// The maximum size of nonce accepted
	MaxNonceSize int64

	// Maximum lag to accept in number of seconds
	AcceptableLag int64

	// Default signature algorithm the server uses
	DefaultSigAlg SignatureAlgorithm

	// The necessary proof-of-work required for the different signature
	// algorithms.
	RequiredProofOfWork map[SignatureAlgorithm]pow.Request
}

// Convenience function to set the Error field
func (resp *Response) SetError(err ErrorCode) {
	resp.Error = &err
}

// Pack time and nonce as one byteslice
func EncodeTimeNonce(time int64, nonce []byte) []byte {
	ret := make([]byte, len(nonce)+8)
	binary.BigEndian.PutUint64(ret, uint64(time))
	copy(ret[8:], nonce)
	return ret
}
