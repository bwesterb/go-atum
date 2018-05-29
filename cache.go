package atum

import (
	"time"
)

var (
	cache Cache
)

// Set the cache used by the Atum client to store server info and public keys.
//
// See the Cache interface.
func SetCache(newCache Cache) {
	cache = newCache
}

// Caches for each known Atum server its public keys (for faster verification)
// and the ServerInfo (for faster stamping).
type Cache interface {

	// Caches that the given public key is valid for the server
	StorePublicKey(serverUrl string, alg SignatureAlgorithm,
		pk []byte, expires time.Time)

	// Returns until when this public key should be trusted for the given
	// server (and nil if the public key is not to be trusted).
	GetPublicKey(serverUrl string, alg SignatureAlgorithm, pk []byte) *time.Time

	// Caches the server information.
	StoreServerInfo(serverUrl string, info ServerInfo)

	//  Retreieves cached server information, if available.
	GetServerInfo(serverUrl string) *ServerInfo
}
