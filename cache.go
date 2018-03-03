package atum

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"

	"encoding/json"
	"log"
	"os"
	"os/user"
	"path"
	"sync"
	"time"
)

var (
	cache Cache
)

func init() {
	cache = &sqlite3Cache{}
}

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

type sqlite3Cache struct {
	db  *gorm.DB
	mux sync.Mutex
}

type serverInfoRecord struct {
	Info   []byte
	Server string `gorm:"unique_index"`
}

type pkRecord struct {
	Pk      []byte `gorm:"index:pk_alg_server"`
	Server  string `gorm:"index:pk_alg_server"`
	Alg     string `gorm:"index:pk_alg_server"`
	Expires time.Time
}

func (cache *sqlite3Cache) ensureOpen() bool {
	if cache.db != nil {
		return true
	}

	usr, err := user.Current()
	if err != nil {
		log.Printf("atum cache: user.Current(): %v", err)
		return false
	}

	cacheDirPath := path.Join(usr.HomeDir, ".cache", "atum")
	if _, err = os.Stat(cacheDirPath); os.IsNotExist(err) {
		err = os.MkdirAll(cacheDirPath, 0700)
		if err != nil {
			log.Printf("atum cache: os.MkdirAll(%s): %v", cacheDirPath, err)
			return false
		}
	}

	cachePath := path.Join(cacheDirPath, "cache.sqlite3")
	cache.db, err = gorm.Open("sqlite3", cachePath)
	if err != nil {
		log.Printf("atum cache: gorm.Open(%s): %v", cachePath, err)
		return false
	}

	if err := cache.db.AutoMigrate(&serverInfoRecord{}, &pkRecord{}).Error; err != nil {
		log.Printf("atum cache: gorm.AutoMigrate(%s): %v", cachePath, err)
		return false
	}
	return true
}

func (cache *sqlite3Cache) StorePublicKey(serverUrl string, alg SignatureAlgorithm,
	pk []byte, expires time.Time) {
	cache.mux.Lock()
	defer cache.mux.Unlock()
	if !cache.ensureOpen() {
		return
	}
	if err := cache.db.Where(&pkRecord{
		Pk:     pk,
		Alg:    string(alg),
		Server: serverUrl,
	}).Assign(&pkRecord{Expires: expires}).FirstOrCreate(&pkRecord{
		Pk:      pk,
		Alg:     string(alg),
		Server:  serverUrl,
		Expires: expires,
	}).Error; err != nil {
		log.Printf("atum cache: StorePublicKey(): %v", err)
	}
}

func (cache *sqlite3Cache) GetPublicKey(serverUrl string,
	alg SignatureAlgorithm, pk []byte) *time.Time {
	cache.mux.Lock()
	defer cache.mux.Unlock()
	if !cache.ensureOpen() {
		return nil
	}
	var record pkRecord
	if cache.db.Where(&pkRecord{
		Pk:     pk,
		Alg:    string(alg),
		Server: serverUrl,
	}).First(&record).RecordNotFound() {
		return nil
	}
	return &record.Expires
}

func (cache *sqlite3Cache) StoreServerInfo(serverUrl string, info ServerInfo) {
	cache.mux.Lock()
	defer cache.mux.Unlock()
	if !cache.ensureOpen() {
		return
	}
	infoBytes, _ := json.Marshal(info)
	if err := cache.db.Where(&serverInfoRecord{
		Server: serverUrl,
	}).Assign(&serverInfoRecord{
		Info: infoBytes,
	}).FirstOrCreate(&serverInfoRecord{
		Info:   infoBytes,
		Server: serverUrl,
	}).Error; err != nil {
		log.Printf("atum cache: StoreServerInfo(): %v", err)
	}
}

func (cache *sqlite3Cache) GetServerInfo(serverUrl string) *ServerInfo {
	cache.mux.Lock()
	defer cache.mux.Unlock()
	if !cache.ensureOpen() {
		return nil
	}
	var record serverInfoRecord
	if cache.db.Where(&serverInfoRecord{
		Server: serverUrl,
	}).First(&record).RecordNotFound() {
		return nil
	}
	var ret ServerInfo
	json.Unmarshal(record.Info, &ret)
	return &ret
}
