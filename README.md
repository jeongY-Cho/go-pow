![Test](https://github.com/jeongY-Cho/go-pow/workflows/Test/badge.svg?branch=master)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/jeongy-cho/go-pow)](https://pkg.go.dev/github.com/jeongy-cho/go-pow)
[![codecov](https://codecov.io/gh/jeongY-Cho/go-pow/branch/master/graph/badge.svg)](https://codecov.io/gh/jeongY-Cho/go-pow)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/jeongy-cho/go-pow)
# Go - Proof of work

Small package implementing a sha256 based proof of work.

## Install

```
go get github.com/jeongY-Cho/go-pow
```

## Usage

### Not Interesting Use

```go
import "github.com/jeongY-Cho/go-pow"

func main() {

  // make an instance with default config
  pow := gopow.New(&Pow{})
  // defaults:
  // 	Secret      ""
  // 	NonceLength 10
  // 	Check       false
  // 	Difficulty  0

  // generate a nonce
  nonceArr, err := pow.GenerateNonce()
  // nonceArr is an array of two strings
  // first element is the nonce
  // second element is a nonce checksum generated when check is true
  nonce := nonceArr[0]


  // some data
  data := getSomeData()

  // make data a string concat with nonce then hash
  hash := SHA256HashFunc(string(data) + nonce)

  // use gopow to verify hash
  ok, err := pow.VerifyHash(nonce, string(data), hash, "")
  // ok will be true on good verify
  // ok will be false and return an error on bad verify
}
```

### Interesting Use

```go
import github.com/jeongY-Cho/go-pow

func main() {

  // make an instance with a config
  pow := gopow.New(&Pow{
    Secret: "thisisasecret",
    NonceLength: 100,
    Check: true,
    Difficulty: 2
  })

  // generate a nonce
  nonceArr, err := pow.GenerateNonce()
  // nonceArr is an array of two strings
  // first element is the nonce
  // second element is a nonce checksum generated when check is true
  nonce := nonceArr[0]
  nonceChecksum := nonceArr[1]

  // some data
  data := getSomeData()

  // make data a string concat with nonce then hash
  hash := SHA256HashFunc(string(data) + nonce[0])

  // use gopow to verify hash
  ok, err := pow.VerifyHashAtDifficulty(nonce, string(data), hash, nonceChecksum)
  // if the hash doesn't have two leading `0` (ie difficulty == 2) then verify
  // will fail
  // if the nonceChecksum is not hash of `nonce + secret` then verify will fail
}
```

### Application: login throttling

1. Client requests a nonce, nonceChecksum and difficulty from server
2. Client calculates a hash with the username + password + randomBits + nonce that fulfills difficulty.
3. Client sends username, password, nonce, nonceChecksum, calculated hash, and the randomBits.
4. Server validates nonce against nonceChecksum, and hash against received data, then proceeds on valid hash.

(alternatively a server could cache nonces instead of calculating checksums)

> q.v. https://www.fastly.com/blog/defend-against-credential-stuffing-attacks-proof-of-work
