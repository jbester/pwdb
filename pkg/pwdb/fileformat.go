package pwdb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"

	"golang.org/x/crypto/hkdf"
)

const magicMarkerFormat = "pwdb%08x"
const magicMarkerLength = 4 + 8

func makeFileMarker(version uint32) []byte {
	return []byte(fmt.Sprintf(magicMarkerFormat, version))
}

const dbVersion = 1

var magicId = makeFileMarker(dbVersion)

const fileIvSize = aes.BlockSize
const aesIvSize = aes.BlockSize
const aesKeySize = 256 / 8
const macSize = 256 / 8

// asserts to check for internal errors
func assertTrue(condition bool, msg string) {
	if !condition {
		_, filename, line, _ := runtime.Caller(1)
		fmt.Printf("Assert failed %s:%d: %s\n", filename, line, msg)
		os.Exit(1)
	}
}

// asserts to check for internal errors
func assertNoError(err error, msg string) {
	if err != nil {
		_, filename, line, _ := runtime.Caller(1)
		fmt.Printf("Assert failed %s:%d %s\nerror: %s\n", filename, line, msg, err.Error())
		os.Exit(1)
	}
}

var DatabaseEncryptedError = errors.New("database encrypted error")
var IncorrectKeyError = errors.New("incorrect key")

func getDbVersion(b []byte) (uint32, error) {
	var dbVersionValue uint32
	_, err := fmt.Sscanf(string(b[:magicMarkerLength]), magicMarkerFormat, &dbVersionValue)
	if err != nil {
		return 0, err
	}
	return dbVersionValue, nil
}

func isValidMagicId(b []byte) bool {
	var ver, err = getDbVersion(b)
	if err != nil {
		return false
	}
	return ver != 0
}

// Test if a file is encrypted
func IsEncrypted(path string) bool {
	var fp, err = os.Open(path)
	var b = make([]byte, len(magicId))
	defer fp.Close()

	if err != nil {
		return false
	}

	if _, err = fp.Read(b); err != nil {
		return false
	}

	// test if encrypted
	return !isValidMagicId(b)
}

var InvalidHMACError = errors.New("invalid HMAC")

// Read a config from the given Reader
func ReadConfig(reader io.Reader, key []byte) (*Database, error) {
	var db Database
	content, err := ioutil.ReadAll(reader)
	assertNoError(err, "could not read config file")

	// test if encrypted
	if !isValidMagicId(content) {
		if key == nil {
			return nil, DatabaseEncryptedError
		}
		// validate HMAC
		if !isHMACValid(key, content) {
			return nil, InvalidHMACError
		}
		// attempt decryption
		var candidate = decrypt(key, content[:len(content)-macSize])
		// test if it's a valid config
		assertTrue(isValidMagicId(candidate), "internal error - valid HMAC invalid contents")
		content = candidate
	}

	// strip off the magic id
	content = content[len(magicId):]
	for i, b := range content {
		if b == 0 {
			content = content[:i]
			break
		}
	}
	// un-marshall account data
	if err = json.Unmarshal(content, &db); err != nil {
		return nil, err
	}

	return &db, nil
}

func LoadConfig(path string, key []byte) (*Database, error) {
	var fp, err = os.Open(path)
	defer fp.Close()
	if err != nil {
		return nil, err
	}
	return ReadConfig(fp, key)
}

// generate a key using HKDF
func kdf(secret []byte, iv []byte) []byte {
	var key = make([]byte, aesKeySize)
	kdf := hkdf.New(sha256.New, secret, iv, magicId[:])
	n, err := kdf.Read(key)
	assertTrue(n == aesKeySize, "key generation error")
	assertNoError(err, "key generation error")
	return key
}

// encrypt
func encrypt(password []byte, iv []byte, plaintext []byte) []byte {
	const minimumIncrement = aes.BlockSize * 100
	if len(iv) != aesIvSize {
		panic("Internal error; iv isn't expected iv size")
	}
	key := kdf(password, iv)
	block, err := aes.NewCipher(key)
	assertNoError(err, "aes new cipher failed")

	var encryptor = cipher.NewCBCEncrypter(block, iv[:aesIvSize])
	var prepaddingSize = len(plaintext)

	// align to minimum increment and aes block size
	if prepaddingSize%minimumIncrement != 0 {
		var paddingSize = minimumIncrement - (prepaddingSize % minimumIncrement)
		var padding = make([]byte, paddingSize)
		n, err := rand.Read(padding[:])
		assertNoError(err, "could not generate new random numbers")
		assertTrue(n == paddingSize, "could not generate new random numbers")
		plaintext = append(plaintext, padding[:]...)
	}

	// encrypt
	var encrypted = make([]byte, fileIvSize+len(plaintext))
	encryptor.CryptBlocks(encrypted[fileIvSize:], plaintext)
	copy(encrypted[:fileIvSize], iv)

	// append hmac after encryption
	mac := hmac.New(sha256.New, key)
	mac.Write(encrypted)
	encrypted = append(encrypted, mac.Sum(nil)...)

	return encrypted
}

func isHMACValid(password []byte, content []byte) bool {
	var iv = content[:fileIvSize]
	key := kdf(password, iv)
	expected := content[len(content)-macSize:]
	payload := content[:len(content)-macSize]

	// mac just the content
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	var m = mac.Sum(nil)

	var ok = true
	for i := 0; i < macSize; i++ {
		ok = expected[i] == m[i] && ok
	}
	return ok
}

// Decrypt assumes any MAC is already removed
func decrypt(password []byte, content []byte) []byte {
	var iv = content[:fileIvSize]
	payload := content[fileIvSize:]

	key := kdf(password, iv)
	block, err := aes.NewCipher(key)

	assertNoError(err, "aes new cipher failed")
	var decrypter = cipher.NewCBCDecrypter(block, iv[:aesIvSize])
	var decrypted = make([]byte, len(payload))
	decrypter.CryptBlocks(decrypted, payload)
	return decrypted
}

// Save a config to a given file location.   It will be created with 600 permissions
func SaveConfig(path string, db *Database, secret []byte) error {
	var permissions os.FileMode = 0600

	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, permissions)
	if err != nil {
		return err
	}

	return WriteConfig(fp, db, secret)
}

// Write a config to the given io.writer
func WriteConfig(writer io.Writer, db *Database, secret []byte) error {
	if db == nil {
		return fmt.Errorf("invalid database")
	}

	data, err := json.Marshal(*db)
	assertNoError(err, "unmarshallable database")

	data = append(magicId, data...)
	data = append(data, 0)
	if secret != nil {
		// NB - IV is used for KDF as well so it's a full AES Block
		var iv = make([]byte, aesIvSize)
		n, err := rand.Read(iv)
		assertTrue(n == aesIvSize, "could not generate secure random")
		assertNoError(err, "could not generate secure random")
		data = encrypt(secret, iv[:aesIvSize], data)
	}
	_, err = writer.Write(data)
	return err
}
