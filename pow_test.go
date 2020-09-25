package gopow

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPow_GenerateNonce(t *testing.T) {
	t.Run("generate nonce with check", func(t *testing.T) {
		nonceLength := 10
		p := &Pow{check: true, nonceLength: nonceLength, secret: "abc"}

		nonce, err := p.GenerateNonce()
		if err != nil {
			t.Fatal("generatenonce returned error")
		}

		if retLen := len(nonce[0]); retLen != nonceLength {
			t.Errorf("incorrect nonce length; Got: %v; Expected: %v", retLen, nonceLength)
		}

		if nonce[1] == "" {
			t.Error("got empty checksum")
		}
	})

	t.Run("generate nonce without check", func(t *testing.T) {
		nonceLength := 10
		p := &Pow{check: false, nonceLength: nonceLength, secret: "abc"}

		nonce, err := p.GenerateNonce()
		if err != nil {
			t.Fatal("generatenonce returned error")
		}

		if retLen := len(nonce[0]); retLen != nonceLength {
			t.Errorf("incorrect nonce length; Got: %v; Expected: %v", retLen, nonceLength)
		}

		if nonce[1] != "" {
			t.Error("got a checksum for non check")
		}

	})

	lens := []int{1, 10, 20, 100}
	for _, l := range lens {
		t.Run(fmt.Sprintf("test generate with nonce length %v", l), func(t *testing.T) {
			p := Pow{
				nonceLength: l,
			}
			nonce, _ := p.GenerateNonce()
			if len(nonce[0]) != l {
				t.Errorf("nonce length mismatch; Got: %v, Expected: %v", len(nonce[0]), l)
			}
		})
	}
}

func TestPow_VerifyHash(t *testing.T) {
	type args struct {
		nonce    string
		data     string
		hash     string
		nonceSig string
	}
	tests := []struct {
		name    string
		p       *Pow
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
		{"verify", New(&PowConfig{}), args{"", "", "", ""}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.p.VerifyHash(tt.args.nonce, tt.args.data, tt.args.hash, tt.args.nonceSig)
			if (err != nil) != tt.wantErr {
				t.Errorf("Pow.VerifyHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Pow.VerifyHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPow_VerifyDifficulty(t *testing.T) {
	type args struct {
		hash string
	}
	tests := []struct {
		name string
		p    *Pow
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.VerifyDifficulty(tt.args.hash); got != tt.want {
				t.Errorf("Pow.VerifyDifficulty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPow_VerifyHashAtDifficulty(t *testing.T) {
	type args struct {
		nonce    string
		data     string
		hash     string
		nonceSig string
	}
	tests := []struct {
		name    string
		p       *Pow
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.p.VerifyHashAtDifficulty(tt.args.nonce, tt.args.data, tt.args.hash, tt.args.nonceSig)
			if (err != nil) != tt.wantErr {
				t.Errorf("Pow.VerifyHashAtDifficulty() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Pow.VerifyHashAtDifficulty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		config *PowConfig
	}
	tests := []struct {
		name string
		args args
		want *Pow
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.config); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
