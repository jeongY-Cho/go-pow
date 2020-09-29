package gopow

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"

	gonanoid "github.com/matoous/go-nanoid"
)

// NonceGenerator function type. takes a length parameter and returns a string.
//   The length parameter is optional; the returned string need not be
//   as long as the length parameter
type NonceGenerator func(int) ([]byte, error)

// HashFunction type.
type HashFunction func([]byte) []byte

// Pow ...
type Pow struct {
	Secret      []byte
	NonceLength int
	Check       bool
	Difficulty  int
	// NonceGenerator method returns a nonce. Takes an integer parameter
	// which is `Pow.NonceLength`. Defaults to `gonanoid.Nanoid`
	NonceGenerator NonceGenerator
	// Hash is a method that hashes a slice of bytes and returns a new slice which is a hash of the slice.
	//   Defaults to `sha256.Sum256`
	Hash HashFunction
}

// GenerateNonce generates a new nonce, also generates signature if verify enabled
func (p *Pow) GenerateNonce() (nonce []byte, checksum []byte, err error) {

	nonce, err = p.NonceGenerator(p.NonceLength)
	if err != nil {
		nonce = []byte{}
		return
	}

	if p.Check {
		checksum = p.Hash(append(nonce, p.Secret...))
	}
	return
}

// VerifyHash verifies the hash given the nonce and data
func (p *Pow) VerifyHash(nonce []byte, data []byte, hash []byte, nonceSig []byte) (bool, error) {
	if p.Check {
		if len(nonceSig) == 0 {
			return false, errors.New("can't verify with empty nonceSig")
		}

		sign := p.Hash(append(nonce, p.Secret...))
		if !bytes.Equal(sign, nonceSig) {
			return false, fmt.Errorf("nonce is invalid. Provided nonce hashed to: <%x> Expected: <%x>", sign, nonceSig)
		}
	}

	hashHere := p.Hash(append(data, nonce...))

	if !bytes.Equal(hashHere, hash) {
		return false, errors.New("failed to verify hash")
	}

	return true, nil
}

// VerifyDifficulty verifies hash fulfils difficulty requirement
func (p *Pow) VerifyDifficulty(hash []byte) bool {

	diff := p.Difficulty

	for _, byte := range hash {
		lead := bits.LeadingZeros8(uint8(byte))
		diff -= lead

		if lead < 8 {
			if diff <= 0 {
				return true
			}
			return false
		}

		if diff <= 0 {
			return true
		}

	}

	return false
}

// VerifyHashAtDifficulty verifies hash and difficulty
func (p *Pow) VerifyHashAtDifficulty(nonce []byte, data []byte, hash []byte, nonceSig []byte) (bool, error) {
	if !p.VerifyDifficulty(hash) {
		return false, fmt.Errorf("failed to verify at difficulty: %v", p.Difficulty)
	}

	return p.VerifyHash(nonce, data, hash, nonceSig)
}

// New helper function to return new pow object with defaults
func New(config *Pow) *Pow {
	if config.NonceLength == 0 {
		config.NonceLength = 10
	}

	if config.NonceGenerator == nil {
		config.NonceGenerator = func(l int) ([]byte, error) {
			nonce, err := gonanoid.Nanoid(l)
			return []byte(nonce), err
		}
	}

	if config.Hash == nil {
		config.Hash = func(b []byte) []byte {
			h := (sha256.Sum256(b))
			return h[:]
		}
	}

	return config
}
