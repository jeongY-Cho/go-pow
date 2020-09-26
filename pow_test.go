package gopow

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPow_GenerateNonce(t *testing.T) {
	t.Run("generate nonce with check", func(t *testing.T) {
		nonceLength := 10
		p := &Pow{Check: true, NonceLength: nonceLength, Secret: "abc"}

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
		p := &Pow{Check: false, NonceLength: nonceLength, Secret: "abc"}

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
				NonceLength: l,
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
		{"check, empty", New(&Pow{Check: true}), args{"", "", "", "a"}, false, true},
		{"no check empty", New(&Pow{}), args{"", "", "", ""}, false, true},
		{"check", New(&Pow{Check: true, Secret: "secret"}), args{"nonce", "data", "2c177eecd4ad52094136dff33d30163ff0e47a95934a5c3e95abbade8700cdfd", "5c420d7fedeb75e1309b1fe82f9c85d5552f1edfc11c72e7749330881166f18d"}, true, false},
		{"check but no checksum", New(&Pow{Check: true, Secret: "secret"}), args{"nonce", "data", "2c177eecd4ad52094136dff33d30163ff0e47a95934a5c3e95abbade8700cdfd", ""}, false, true},
		{"no check", New(&Pow{Check: false}), args{"nonce", "data", "2c177eecd4ad52094136dff33d30163ff0e47a95934a5c3e95abbade8700cdfd", ""}, true, false},
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
		{"test diff 0", New(&Pow{}), args{"adfsj;kladfsj;kladfs"}, true},
		{"test diff 1", New(&Pow{Difficulty: 1}), args{"adfsj;kladfsj;kladfs"}, false},
		{"test diff 0", New(&Pow{Difficulty: 1}), args{"0adfsj;kladfsj;kladfs"}, true},
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
		{"good hash, bad diff", New(&Pow{Check: true, Secret: "secret", Difficulty: 1}), args{"nonce", "data", "2c177eecd4ad52094136dff33d30163ff0e47a95934a5c3e95abbade8700cdfd", "5c420d7fedeb75e1309b1fe82f9c85d5552f1edfc11c72e7749330881166f18d"}, false, true},
		{"good hash, good diff", New(&Pow{Check: true, Secret: "secret", Difficulty: 1}), args{"nonce", "data11222222222222222221", "0b891de4a7ca9eaf65ea443e72980a2acd63d00caa9f2f431885ee16939bba99", "5c420d7fedeb75e1309b1fe82f9c85d5552f1edfc11c72e7749330881166f18d"}, true, false},
		{"bad hash, good diff", New(&Pow{Check: true, Secret: "secret", Difficulty: 1}), args{"nonce", "data11222222222222222221", "0b8912e4a7ca9eaf65ea443e72980a2acd63d00caa9f2f431885ee16939bba99", "5c420d7fedeb75e1309b1fe82f9c85d5552f1edfc11c72e7749330881166f18d"}, false, true},
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
		config *Pow
	}
	tests := []struct {
		name string
		args args
		want *Pow
	}{
		// TODO: Add test cases.
		{"check proper defaults", args{&Pow{}}, &Pow{NonceLength: 10}},
		{"check proper sets", args{&Pow{Secret: "abc", Check: true, Difficulty: 10, NonceLength: 5}}, &Pow{Secret: "abc", Check: true, Difficulty: 10, NonceLength: 5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.config); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
