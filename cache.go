package atum

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"sync"
	"time"

	"github.com/coreos/bbolt"
	"github.com/timshannon/bolthold"
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

func init() {
	cache = &boltCache{}
}

type boltCache struct {
	mux  sync.Mutex
	db   *bolthold.Store
	path string
}

func pkKey(serverUrl string, alg SignatureAlgorithm, pk []byte) string {
	return fmt.Sprintf("%x-%s-%s", pk, alg, serverUrl)
}

func (cache *boltCache) exit() {
	if cache.db != nil {
		if err := cache.db.Close(); err != nil {
			log.Printf("atum cache: %v", err)
		}
		cache.db = nil
	}
	cache.mux.Unlock()
}

func (cache *boltCache) enter(write bool) bool {
	cache.mux.Lock()
	if cache.path == "" {
		usr, err := user.Current()
		if err != nil {
			log.Printf("atum cache: user.Current(): %v", err)
			cache.mux.Unlock()
			return false
		}

		cacheDirPath := path.Join(usr.HomeDir, ".cache", "atum")
		if _, err = os.Stat(cacheDirPath); os.IsNotExist(err) {
			err = os.MkdirAll(cacheDirPath, 0700)
			if err != nil {
				log.Printf("atum cache: os.MkdirAll(%s): %v", cacheDirPath, err)
				cache.mux.Unlock()
				return false
			}
		}

		cache.path = path.Join(cacheDirPath, "cache.bolt")
	}

	var err error
	cache.db, err = bolthold.Open(cache.path, 0600, &bolthold.Options{
		Options: &bolt.Options{
			ReadOnly: !write,
		},
	})
	if err != nil {
		log.Printf("atum cache: bolthold.Open(%s): %v", cache.path, err)
		cache.mux.Unlock()
		return false
	}

	return true
}

func (cache *boltCache) StorePublicKey(serverUrl string, alg SignatureAlgorithm,
	pk []byte, expires time.Time) {
	if !cache.enter(true) {
		return
	}
	defer cache.exit()
	if err := cache.db.Upsert(pkKey(serverUrl, alg, pk), &expires); err != nil {
		log.Printf("atum cache: StorePublicKey(): %v", err)
	}
}

func (cache *boltCache) GetPublicKey(serverUrl string,
	alg SignatureAlgorithm, pk []byte) *time.Time {
	if !cache.enter(false) {
		return nil
	}
	defer cache.exit()
	var ret time.Time
	if err := cache.db.Get(pkKey(serverUrl, alg, pk), &ret); err != nil {
		if err != bolthold.ErrNotFound {
			log.Printf("atum cache: GetPublicKey(): %v", err)
		}
		return nil
	}
	return &ret
}

func (cache *boltCache) StoreServerInfo(serverUrl string, info ServerInfo) {
	if !cache.enter(true) {
		return
	}
	defer cache.exit()
	if err := cache.db.Upsert(serverUrl, &info); err != nil {
		log.Printf("atum cache: StoreServerInfo(): %v", err)
	}
}

func (cache *boltCache) GetServerInfo(serverUrl string) *ServerInfo {
	if !cache.enter(false) {
		return nil
	}
	defer cache.exit()
	var ret ServerInfo
	if err := cache.db.Get(serverUrl, &ret); err != nil {
		if err != bolthold.ErrNotFound {
			log.Printf("atum cache: GetServerInfo(): %v", err)
		}
		return nil
	}
	return &ret
}
