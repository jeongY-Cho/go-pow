package gopow

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	gonanoid "github.com/matoous/go-nanoid"
)

// Pow ...
type Pow struct {
	Secret      string
	NonceLength int
	Check       bool
	Difficulty  int
	// NonceGenerator method returns a nonce. Takes an integer parameter
	// which is `Pow.NonceLength`
	NonceGenerator func(int) (string, error)
	Hash           func([]byte) []byte
}

// GenerateNonce generates a new nonce, also generates signature if verify enabled
func (p *Pow) GenerateNonce() ([2]string, error) {
	returnArr := [2]string{}

	var err error
	returnArr[0], err = p.NonceGenerator(p.NonceLength)
	if err != nil {
		return returnArr, err
	}

	if !p.Check {
		return returnArr, nil
	}

	hash := p.Hash([]byte(returnArr[0] + p.Secret))
	returnArr[1] = hex.EncodeToString(hash[:])
	return returnArr, nil
}

// VerifyHash verifies the hash given the nonce and data
func (p *Pow) VerifyHash(nonce string, data string, hash string, nonceSig string) (bool, error) {
	if p.Check {
		if nonceSig == "" {
			return false, errors.New("can't verify with empty nonceSig")
		}

		sign := p.Hash([]byte(nonce + p.Secret))
		if strSign := hex.EncodeToString(sign[:]); strSign != nonceSig {
			return false, fmt.Errorf("nonce is invalid. Provided nonce hashed to: <%v> Expected: <%v>", strSign, nonceSig)
		}
	}

	hashHere := p.Hash([]byte(data + nonce))

	if hex.EncodeToString(hashHere[:]) != hash {
		return false, errors.New("failed to verify hash")
	}

	return true, nil
}

// VerifyDifficulty verifies hash fulfils difficulty requirement
func (p *Pow) VerifyDifficulty(hash string) bool {
	return strings.HasPrefix(hash, strings.Repeat("0", p.Difficulty))
}

// VerifyHashAtDifficulty verifies hash and difficulty
func (p *Pow) VerifyHashAtDifficulty(nonce string, data string, hash string, nonceSig string) (bool, error) {
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
		config.NonceGenerator = func(l int) (string, error) {
			return gonanoid.Nanoid(l)
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
