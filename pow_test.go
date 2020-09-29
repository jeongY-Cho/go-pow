package gopow

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	gonanoid "github.com/matoous/go-nanoid"
)

func mockNonceGenerator(i int) ([]byte, error) {
	return bytes.Repeat([]byte{0}, i), nil
}
func mockErrorNonceGenerator(i int) ([]byte, error) {
	return nil, errors.New("")
}

var testSecret = []byte("secret")
var testHash1 = []byte{7, 142, 4, 240, 16, 0, 171, 248, 239, 218, 3, 4, 90, 237, 222, 124, 74, 84, 3, 54, 140, 208, 54, 141, 209, 25, 177, 173, 72, 226, 132, 183}

func TestPow_GenerateNonce(t *testing.T) {
	type fields struct {
		Secret         []byte
		NonceLength    int
		Check          bool
		Difficulty     int
		NonceGenerator NonceGenerator
		Hash           HashFunction
	}
	tests := []struct {
		name         string
		fields       fields
		wantNonce    []byte
		wantChecksum []byte
		wantErr      bool
	}{
		{"generate with check", fields{Check: true, Secret: testSecret, NonceGenerator: mockNonceGenerator}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, testHash1, false},
		{"generate without check", fields{Secret: testSecret, NonceGenerator: mockNonceGenerator}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte(nil), false},
		{"generate different length", fields{NonceLength: 11, Secret: testSecret, NonceGenerator: mockNonceGenerator}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte(nil), false},
		{"noncegenerate errors", fields{Secret: testSecret, NonceGenerator: mockErrorNonceGenerator}, []byte{}, []byte(nil), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(&Pow{
				Secret:         tt.fields.Secret,
				NonceLength:    tt.fields.NonceLength,
				Check:          tt.fields.Check,
				Difficulty:     tt.fields.Difficulty,
				NonceGenerator: tt.fields.NonceGenerator,
				Hash:           tt.fields.Hash,
			})
			gotNonce, gotChecksum, err := p.GenerateNonce()
			if (err != nil) != tt.wantErr {
				t.Errorf("Pow.GenerateNonce() error = %#v, wantErr %#v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotNonce, tt.wantNonce) {
				t.Errorf("Pow.GenerateNonce() gotNonce = %#v, want %#v", gotNonce, tt.wantNonce)
			}
			if !reflect.DeepEqual(gotChecksum, tt.wantChecksum) {
				t.Errorf("Pow.GenerateNonce() gotChecksum = %#v, want %#v", gotChecksum, tt.wantChecksum)
			}
		})
	}
}

func TestPow_VerifyHash(t *testing.T) {
	nonce, _ := mockNonceGenerator(10)
	nonceSig := sha256.Sum256(append(nonce, testSecret...))
	data := []byte("data")
	testHash := []byte{86, 169, 122, 123, 158, 200, 209, 207, 229, 17, 165, 76, 125, 108, 77, 184, 206, 83, 30, 233, 52, 2, 248, 50, 138, 185, 83, 7, 59, 68, 30, 144}
	type fields struct {
		Secret         []byte
		NonceLength    int
		Check          bool
		Difficulty     int
		NonceGenerator NonceGenerator
		Hash           HashFunction
	}
	type args struct {
		nonce    []byte
		data     []byte
		hash     []byte
		nonceSig []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{"verify err on bad hash", fields{}, args{nonce: nonce, data: []byte{}, hash: []byte{}, nonceSig: []byte{}}, false, true},
		{"verify hash", fields{}, args{nonce: nonce, data: data, hash: testHash, nonceSig: []byte{}}, true, false},
		{"verify hash with check", fields{Check: true, Secret: testSecret}, args{nonce: nonce, data: data, hash: testHash, nonceSig: nonceSig[:]}, true, false},
		{"hash with check, no sig", fields{Check: true, Secret: testSecret}, args{nonce: nonce, data: data, hash: testHash, nonceSig: []byte{}}, false, true},
		{"hash with check, bad sig", fields{Check: true, Secret: testSecret}, args{nonce: nonce, data: data, hash: testHash, nonceSig: []byte{1, 2, 3}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(&Pow{
				Secret:         tt.fields.Secret,
				NonceLength:    tt.fields.NonceLength,
				Check:          tt.fields.Check,
				Difficulty:     tt.fields.Difficulty,
				NonceGenerator: tt.fields.NonceGenerator,
				Hash:           tt.fields.Hash,
			})
			got, _ := p.VerifyHash(tt.args.nonce, tt.args.data, tt.args.hash, tt.args.nonceSig)
			// if (err != nil) != tt.wantErr {
			// 	t.Errorf("Pow.VerifyHash() error = %#v, wantErr %#v", err, tt.wantErr)
			// 	return
			// }
			if got != tt.want {
				t.Errorf("Pow.VerifyHash() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestPow_VerifyDifficulty(t *testing.T) {
	type fields struct {
		Secret         []byte
		NonceLength    int
		Check          bool
		Difficulty     int
		NonceGenerator NonceGenerator
		Hash           HashFunction
	}
	type args struct {
		hash []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{"empty hash", fields{}, args{[]byte{}}, false},
		{"difficulty 8", fields{}, args{[]byte{0}}, true},
		{"difficulty 1", fields{Difficulty: 1}, args{[]byte{255, 0}}, false},
		{"difficulty 9", fields{Difficulty: 9}, args{[]byte{0, 127}}, true},
		{"difficulty 9 fail", fields{Difficulty: 9}, args{[]byte{0, 255, 0}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(&Pow{
				Secret:         tt.fields.Secret,
				NonceLength:    tt.fields.NonceLength,
				Check:          tt.fields.Check,
				Difficulty:     tt.fields.Difficulty,
				NonceGenerator: tt.fields.NonceGenerator,
				Hash:           tt.fields.Hash,
			})
			if got := p.VerifyDifficulty(tt.args.hash); got != tt.want {
				t.Errorf("Pow.VerifyDifficulty() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestPow_VerifyHashAtDifficulty(t *testing.T) {
	nonce, _ := mockNonceGenerator(10)
	nonceSig := sha256.Sum256(append(nonce, testSecret...))
	data := []byte("data")
	testHash := []byte{86, 169, 122, 123, 158, 200, 209, 207, 229, 17, 165, 76, 125, 108, 77, 184, 206, 83, 30, 233, 52, 2, 248, 50, 138, 185, 83, 7, 59, 68, 30, 144}

	type fields struct {
		Secret         []byte
		NonceLength    int
		Check          bool
		Difficulty     int
		NonceGenerator NonceGenerator
		Hash           HashFunction
	}
	type args struct {
		nonce    []byte
		data     []byte
		hash     []byte
		nonceSig []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{"good hash, good diff", fields{Difficulty: 1}, args{nonce: nonce, data: data, nonceSig: nonceSig[:], hash: testHash}, true, false},
		{"good hash, bad diff", fields{Difficulty: 1}, args{hash: []byte{255}}, false, true},
		{"bad hash, good diff", fields{}, args{hash: []byte{0}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(&Pow{
				Secret:         tt.fields.Secret,
				NonceLength:    tt.fields.NonceLength,
				Check:          tt.fields.Check,
				Difficulty:     tt.fields.Difficulty,
				NonceGenerator: tt.fields.NonceGenerator,
				Hash:           tt.fields.Hash,
			})
			got, err := p.VerifyHashAtDifficulty(tt.args.nonce, tt.args.data, tt.args.hash, tt.args.nonceSig)
			if (err != nil) != tt.wantErr {
				t.Errorf("Pow.VerifyHashAtDifficulty() error = %#v, wantErr %#v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Pow.VerifyHashAtDifficulty() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	p := New(&Pow{})

	if expect := 10; p.NonceLength != expect {
		t.Errorf("didn't receive expected val for default Pow.Difficulty; Got: %v, Expected: %v", p.NonceLength, expect)
	}

	if l, err := p.NonceGenerator(10); len(l) != 10 {
		if err != nil {
			t.Error("got err: ", err)
		}
		t.Errorf("len of default generator not 10: got %v", len(l))
	}

	a, _ := gonanoid.Nanoid()
	testBytes := []byte(a)
	defaultHash := sha256.Sum256(testBytes)
	shouldBeDefaultHash := p.Hash(testBytes)

	if !reflect.DeepEqual(defaultHash[:], shouldBeDefaultHash) {
		t.Errorf("default has isn't sha256: Got %v expected %v", defaultHash[:], shouldBeDefaultHash)
	}
}
