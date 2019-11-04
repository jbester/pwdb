package pwdb

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSaveInvalidDb(t *testing.T) {
	var buf = &bytes.Buffer{}
	// write
	err := WriteConfig(buf, nil, nil)
	assert.Error(t, err, "Write failed")
}

func TestLoadSaveEmptyDb(t *testing.T) {
	var db = NewDatabase()
	var buf = &bytes.Buffer{}
	// write
	err := WriteConfig(buf, db, nil)
	assert.NoError(t, err, "Write failed")

	// read it back
	c, err := ReadConfig(bytes.NewReader(buf.Bytes()), nil)
	assert.NoError(t, err, "Read failed")
	assert.NotNil(t, c, "Invalid config")
	assert.True(t, len(c.TotpAccounts) == 0, "Unexpected accounts")
	assert.True(t, len(c.Passwords) == 0, "Unexpected passwords")
}

func TestLoadSaveInvalidHMAC(t *testing.T) {
	var db = NewDatabase()
	var buf = &bytes.Buffer{}
	var secret = []byte("some secret")
	// write
	err := WriteConfig(buf, db, secret)
	assert.NoError(t, err, "Write failed")

	// read it back
	var encrypted = buf.Bytes()
	encrypted[len(encrypted)-64] = encrypted[len(encrypted)-64] ^ 0xFF
	_, err = ReadConfig(bytes.NewReader(encrypted), secret)
	assert.Error(t, err, "Read succeeded")
}

func TestLoadSaveUnencryptedDbFile(t *testing.T) {
	var db = NewDatabase()
	db.TotpAccounts["Something"] = TotpEntry{Secret: "some secret"}
	db.Passwords["Something else"] = PasswordEntry{
		Username: "loginame@example.com",
		Password: "some secret"}

	var tempFolder = os.TempDir()
	var tempFile = filepath.Join(tempFolder, fmt.Sprintf("tmp%x.dat", rand.Int()))

	// write it out
	err := SaveConfig(tempFile, db, nil)
	assert.NoError(t, err, "Write failed")

	// check if it's encrypted
	assert.False(t, IsEncrypted(tempFile))

	// read it back
	c, err := LoadConfig(tempFile, nil)
	assert.NoError(t, err, "Read failed")
	assert.NotNil(t, c, "Invalid config")
	assert.True(t, reflect.DeepEqual(*c, *db), "Database don't match")
	os.Remove(tempFile)
}

func TestIsEncryptedUnreadableFile(t *testing.T) {
	var tempFolder = os.TempDir()
	var tempFile = filepath.Join(tempFolder, fmt.Sprintf("tmp%x.dat", rand.Int()))
	var fp, err = os.OpenFile(tempFile, os.O_RDWR|os.O_CREATE, 0)
	assert.NoError(t, err)
	fp.Close()
	assert.False(t, IsEncrypted(tempFile))
	os.Remove(tempFile)
}

func TestIsEncryptedInUnreadableFile(t *testing.T) {
	var tempFolder = os.TempDir()
	var tempFile = filepath.Join(tempFolder, fmt.Sprintf("tmp%x.dat", rand.Int()))

	c, err := LoadConfig(tempFile, nil)
	assert.Error(t, err, "Read failed")
	assert.Nil(t, c, "Invalid config")
}

func TestLoadSaveEncryptedDbFile(t *testing.T) {
	var db = NewDatabase()
	var secret = []byte("some secret password")
	db.TotpAccounts["Something"] = TotpEntry{Secret: "some secret"}
	db.Passwords["Something else"] = PasswordEntry{
		Username: "loginame@example.com",
		Password: "some secret"}

	var tempFolder = os.TempDir()
	var tempFile = filepath.Join(tempFolder, fmt.Sprintf("tmp%x.dat", rand.Int()))

	// write it out
	err := SaveConfig(tempFile, db, secret)
	assert.NoError(t, err, "Write failed")

	// check if it's encrypted
	assert.True(t, IsEncrypted(tempFile))

	// read it back
	c, err := LoadConfig(tempFile, secret)
	assert.NoError(t, err, "Read failed")
	assert.NotNil(t, c, "Invalid config")
	assert.True(t, reflect.DeepEqual(*c, *db), "Database don't match")
	os.Remove(tempFile)
}

func TestLoadSaveEncryptedDbFileIncorrectPassword(t *testing.T) {
	var db = NewDatabase()
	var secret = []byte("some secret password")
	db.TotpAccounts["Something"] = TotpEntry{Secret: "some secret"}
	db.Passwords["Something else"] = PasswordEntry{
		Username: "loginame@example.com",
		Password: "some secret"}

	var tempFolder = os.TempDir()
	var tempFile = filepath.Join(tempFolder, fmt.Sprintf("tmp%x.dat", rand.Int()))
	// write it out
	err := SaveConfig(tempFile, db, secret)
	assert.NoError(t, err, "Write failed")

	// read it back
	c, err := LoadConfig(tempFile, []byte("some other secret password"))
	assert.Error(t, err, "Read failed")
	assert.Nil(t, c, "Valid config")
	os.Remove(tempFile)
}

func TestLoadEncryptedDbWithoutPassword(t *testing.T) {
	var db = NewDatabase()
	var secret = []byte("some secret password")
	db.TotpAccounts["Something"] = TotpEntry{Secret: "some secret"}
	db.Passwords["Something else"] = PasswordEntry{
		Username: "loginame@example.com",
		Password: "some secret"}

	var tempFolder = os.TempDir()
	var tempFile = filepath.Join(tempFolder, fmt.Sprintf("tmp%x.dat", rand.Int()))
	// write it out
	var err = SaveConfig(tempFile, db, secret)
	assert.NoError(t, err, "Write failed")

	// read it back
	_, err = LoadConfig(tempFile, nil)
	assert.True(t, errors.Is(err, DatabaseEncryptedError), "Read failed")
	os.Remove(tempFile)
}
