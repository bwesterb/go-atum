// +build !cgo

package atum

import (
	"fmt"
	"sync"
	"time"
)

func init() {
	cache = newDummyCache()
}

type dummyCache struct {
	mux       sync.Mutex
	pkLut     map[string]time.Time
	serverLut map[string]ServerInfo
}

func newDummyCache() *dummyCache {
	ret := dummyCache{
		serverLut: make(map[string]ServerInfo),
		pkLut:     make(map[string]time.Time),
	}
	return &ret
}

func pkKey(serverUrl string, alg SignatureAlgorithm, pk []byte) string {
	return fmt.Sprintf("%x-%d-%s", pk, alg, serverUrl)
}

func (cache *dummyCache) StorePublicKey(serverUrl string, alg SignatureAlgorithm,
	pk []byte, expires time.Time) {
	cache.mux.Lock()
	defer cache.mux.Unlock()
	cache.pkLut[pkKey(serverUrl, alg, pk)] = expires
}

func (cache *dummyCache) GetPublicKey(serverUrl string, alg SignatureAlgorithm,
	pk []byte) *time.Time {
	cache.mux.Lock()
	defer cache.mux.Unlock()
	expires, ok := cache.pkLut[pkKey(serverUrl, alg, pk)]
	if !ok {
		return nil
	}
	return &expires
}

func (cache *dummyCache) StoreServerInfo(serverUrl string, info ServerInfo) {
	cache.mux.Lock()
	defer cache.mux.Unlock()
	cache.serverLut[serverUrl] = info
}

func (cache *dummyCache) GetServerInfo(serverUrl string) *ServerInfo {
	cache.mux.Lock()
	defer cache.mux.Unlock()
	info, ok := cache.serverLut[serverUrl]
	if !ok {
		return nil
	}
	return &info
}
