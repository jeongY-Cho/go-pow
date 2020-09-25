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
	secret      string
	nonceLength int
	check       bool
	difficulty  int
}

// GenerateNonce generates a new nonce, also generates signature if verify enabled
func (p *Pow) GenerateNonce() ([2]string, error) {
	returnArr := [2]string{}

	var err error
	returnArr[0], err = gonanoid.ID(p.nonceLength)
	if err != nil {
		return [2]string{}, err
	}

	if !p.check {
		return returnArr, nil
	}

	hash := sha256.Sum256([]byte(returnArr[0] + p.secret))
	returnArr[1] = hex.EncodeToString(hash[:])
	return returnArr, nil
}

// VerifyHash verifies the hash given the nonce and data
func (p *Pow) VerifyHash(nonce string, data string, hash string, nonceSig string) (bool, error) {
	if p.check {
		if nonceSig == "" {
			return false, errors.New("can't verify with empty nonceSig")
		}

		sign := sha256.Sum256([]byte(nonce + p.secret))
		if strSign := hex.EncodeToString(sign[:]); strSign != nonceSig {
			return false, fmt.Errorf("nonce is invalid. Provided nonce hashed to: <%v> Expected: <%v>", strSign, nonceSig)
		}
	}

	hashHere := sha256.Sum256([]byte(data + nonce))

	if hex.EncodeToString(hashHere[:]) != hash {
		return false, errors.New("failed to verify hash")
	}

	return true, nil
}

// VerifyDifficulty verifies hash fulfils difficulty requirement
func (p *Pow) VerifyDifficulty(hash string) bool {
	return strings.HasPrefix(hash, strings.Repeat("0", p.difficulty))
}

// VerifyHashAtDifficulty verifies hash and difficulty
func (p *Pow) VerifyHashAtDifficulty(nonce string, data string, hash string, nonceSig string) (bool, error) {
	if !p.VerifyDifficulty(hash) {
		return false, fmt.Errorf("failed to verify at difficulty: %v", p.difficulty)
	}

	return p.VerifyHash(nonce, data, hash, nonceSig)
}

// PowConfig config struct for a new proof-of-work object
type PowConfig struct {
	secret      string
	nonceLength int
	verify      bool
	difficulty  int
}

// New helper function to return new pow object with defaults
func New(config *PowConfig) *Pow {
	nonceLength := config.nonceLength
	if nonceLength == 0 {
		nonceLength = 10
	}

	return &Pow{
		secret:      config.secret,
		nonceLength: nonceLength,
		check:       config.verify,
		difficulty:  config.difficulty,
	}
}
