// Atum is a post-quantum secure easy-to-use trusted time-stamping protocol.
package atum

// A nonce with a signature
type Timestamp struct {

	// The unix time at which the timestamp was set
	Time int64

	// The signature.
	Sig Signature
}

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

type ErrorCode string

const (
	// There is no error
	NoErrorCode ErrorCode = ""

	// There is too much lag
	ErrorCodeLag = "lag"
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
	MaxNonceSize int

	// Maximum lag to accept in number of seconds
	AcceptableLag int

	// Default signature algorithm the server uses
	DefaultSigAlg SignatureAlgorithm
}
