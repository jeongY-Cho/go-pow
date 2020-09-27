package gopow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	gonanoid "github.com/matoous/go-nanoid"
)

func TestPow_GenerateNonce(t *testing.T) {
	t.Run("generate nonce with check", func(t *testing.T) {
		nonceLength := 10
		p := New(&Pow{Check: true, NonceLength: nonceLength, Secret: "abc"})

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
		p := New(&Pow{Check: false, NonceLength: nonceLength, Secret: "abc"})

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
			p := New(&Pow{
				NonceLength: l,
			})
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
	t.Run("check proper defaults", func(t *testing.T) {
		p := New(&Pow{})
		q := &Pow{NonceLength: 10}
		e := reflect.ValueOf(p).Elem()
		d := reflect.ValueOf(q).Elem()
		funcNames := make(map[string]int, 0)

		for i := 0; i < e.NumField(); i++ {
			varName := e.Type().Field(i).Name
			varType := e.Type().Field(i).Type
			varKind := varType.Kind()
			if varKind == reflect.Func {
				funcNames[varName] = 1
				continue
			}

			dvar, _ := d.Type().FieldByName(varName)

			varValue := e.Field(i).Interface()
			dval := d.FieldByName(dvar.Name).Interface()

			if !reflect.DeepEqual(varValue, dval) {
				t.Errorf("%v is not equal to test default", varName)
			}

		}

		t.Run("test default NonceGenerator", func(t *testing.T) {

			x, err := p.NonceGenerator(p.NonceLength)
			if err != nil {
				t.Error("error in default nonceGenerator")
			}

			if len(x) != p.NonceLength {
				t.Error("default nonce generator is not returning proper length")
			}

			if !t.Failed() {
				delete(funcNames, "NonceGenerator")
			}

		})

		t.Run("test default hash", func(t *testing.T) {
			test, _ := gonanoid.ID(20)
			sha256sum := sha256.Sum256([]byte(test))

			if !reflect.DeepEqual(p.Hash([]byte(test)), sha256sum[:]) {

				t.Errorf("Default hash didn't hash properly; Got: %v, Expected: %v", hex.EncodeToString(p.Hash([]byte(test))), hex.EncodeToString(sha256sum[:]))
			} else {
				delete(funcNames, "Hash")
			}
		})

		if len(funcNames) > 0 {
			t.Errorf("Untested Default methods: %v", funcNames)
		}
	})

	t.Run("check proper sets", func(t *testing.T) {
		p := New(&Pow{Secret: "abc", Check: true, Difficulty: 10, NonceLength: 5, NonceGenerator: func(i int) (string, error) {
			return "test", nil
		}, Hash: func(b []byte) []byte { return []byte("abc") }})

		q := &Pow{Secret: "abc", Check: true, Difficulty: 10, NonceLength: 5, NonceGenerator: func(i int) (string, error) {
			return "test", nil
		}, Hash: func(b []byte) []byte { return []byte("abc") }}
		e := reflect.ValueOf(p).Elem()
		d := reflect.ValueOf(q).Elem()
		funcNames := make(map[string]int, 0)

		for i := 0; i < e.NumField(); i++ {
			varName := e.Type().Field(i).Name
			varType := e.Type().Field(i).Type
			varKind := varType.Kind()
			if varKind == reflect.Func {
				funcNames[varName] = 1
				continue
			}

			dvar, _ := d.Type().FieldByName(varName)

			varValue := e.Field(i).Interface()
			dval := d.FieldByName(dvar.Name).Interface()

			if !reflect.DeepEqual(varValue, dval) {
				t.Errorf("%v is not equal to test default", varName)
			}
		}
		t.Run("test set NonceGenerator", func(t *testing.T) {

			x, _ := p.NonceGenerator(p.NonceLength)
			y, _ := q.NonceGenerator(q.NonceLength)

			if x != y {
				t.Errorf("New().NonceGenerator not equal to set one; Got %v, Expected: %v", x, y)
			}

			if !t.Failed() {
				delete(funcNames, "NonceGenerator")
			}

		})
		t.Run("test set Hash", func(t *testing.T) {
			a := p.Hash([]byte("a"))
			if b := p.Hash([]byte("b")); !reflect.DeepEqual(a, b) {
				t.Errorf("set Hash func didn't return same, Got: %v, Expected: %v", a, b)
			} else {
				if !reflect.DeepEqual(a, []byte("abc")) {
					t.Errorf("set didn't return []byte('abc')")
				} else {
					delete(funcNames, "Hash")
				}
			}
		})

		if len(funcNames) > 0 {
			t.Errorf("Untested Default methods: %v", funcNames)
		}
	})
}
