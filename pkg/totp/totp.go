package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"hash"
	"strings"
	"time"

	"bitbucket.org/jbester/binaryio"
)

func calculateHotp(algorithm func() hash.Hash, secret []byte, intervals_no int64) (uint32, error) {
	if secret == nil {
		return 0, fmt.Errorf("invalid secret")
	}
	var writer = binaryio.BigEndianBufferWriter()
	writer.WriteUint64(uint64(intervals_no))
	msg := writer.Bytes()
	h := hmac.New(algorithm, secret)
	h.Write(msg)
	digest := h.Sum(nil)
	o := digest[19] & 15
	var reader = binaryio.BigEndianBufferReader(digest[o : o+4])
	token, err := reader.ReadUint32()
	token &= 0x7fffffff
	token %= 1000000
	return token, err
}

type Secret []byte

type Generator struct {
	Algorithm func() hash.Hash
	Secret
	TimeStep int64
}

func Base32Secret(secret string) (Secret, error) {
	const Size = 8
	if len(secret)%Size != 0 {
		secret += strings.Repeat("=", Size-(len(secret)%Size))
	}

	key, err := base32.StdEncoding.DecodeString(secret)
	return key, err
}

func NewGenerator(secret Secret) Generator {
	return Generator{TimeStep: 30, Algorithm: sha1.New, Secret: secret}

}

func (generator Generator) Calculate(time time.Time) (uint32, error) {
	return calculateHotp(generator.Algorithm, generator.Secret, time.Unix()/generator.TimeStep)
}

func (generator Generator) Now() (uint32, error) {
	return generator.Calculate(time.Now())
}
