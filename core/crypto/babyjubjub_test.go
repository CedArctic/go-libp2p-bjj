package crypto

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"google.golang.org/protobuf/proto"
)

// TestBasicSignAndVerify tests the basic sign and verify functionality.
func TestBasicSignAndVerifyBJJ(t *testing.T) {
	priv, pub, err := GenerateBJJKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello! and welcome to some awesome crypto primitives")

	sig, err := priv.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("signature didn't match")
	}

	// change data
	data[0] = ^data[0]
	ok, err = pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}

	if ok {
		t.Fatal("signature matched and shouldn't")
	}
}

// TestSignZero tests signing with zero-length data.
func TestSignZeroBJJ(t *testing.T) {
	priv, pub, err := GenerateBJJKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 0)
	sig, err := priv.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature didn't match")
	}
}

// TestMarshalLoop tests marshaling and unmarshaling keys.
func TestMarshalLoopBJJ(t *testing.T) {
	priv, pub, err := GenerateBJJKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("PrivateKey", func(t *testing.T) {
		bts, err := MarshalPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}

		privNew, err := UnmarshalPrivateKey(bts)
		if err != nil {
			t.Fatal(err)
		}

		if !priv.Equals(privNew) || !privNew.Equals(priv) {
			t.Fatal("keys are not equal")
		}

		msg := []byte("My child, my sister,\nThink of the rapture\nOf living together there!")
		signed, err := privNew.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}

		ok, err := privNew.GetPublic().Verify(msg, signed)
		if err != nil {
			t.Fatal(err)
		}

		if !ok {
			t.Fatal("signature didn't match")
		}
	})

	t.Run("PublicKey", func(t *testing.T) {
		bts, err := MarshalPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		pubNew, err := UnmarshalPublicKey(bts)
		if err != nil {
			t.Fatal(err)
		}

		if !pub.Equals(pubNew) || !pubNew.Equals(pub) {
			t.Fatal("keys are not equal")
		}
	})
}

// TestUnmarshalErrors tests unmarshaling with invalid data.
func TestUnmarshalErrorsBJJ(t *testing.T) {
	t.Run("PublicKey", func(t *testing.T) {
		t.Run("Invalid data", func(t *testing.T) {
			data, err := proto.Marshal(&pb.PublicKey{
				Type: pb.KeyType_Babyjubjub.Enum(),
				Data: []byte{42},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalPublicKey(data); err == nil {
				t.Fatal("expected an error")
			}
		})
	})

	t.Run("PrivateKey", func(t *testing.T) {
		t.Run("Invalid data length", func(t *testing.T) {
			data, err := proto.Marshal(&pb.PrivateKey{
				Type: pb.KeyType_Babyjubjub.Enum(),
				Data: []byte{42},
			})
			if err != nil {
				t.Fatal(err)
			}

			_, err = UnmarshalPrivateKey(data)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	})
}

// TestPrivateKeyEquals tests the Equals method for private keys.
func TestPrivateKeyEqualsBJJ(t *testing.T) {
	privA, _, err := GenerateBJJKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Self equals", func(t *testing.T) {
		if !privA.Equals(privA) {
			t.Fatal("private key not equal to itself")
		}
	})

	t.Run("Same key equals", func(t *testing.T) {
		privB, _, err := BJJKeyPairFromKey(privA.(*BJJPrivateKey).priv)
		if err != nil {
			t.Fatal(err)
		}
		if !privA.Equals(privB) {
			t.Fatal("same key did not equal")
		}
	})

	t.Run("Different key not equals", func(t *testing.T) {
		privB, _, err := GenerateBJJKeyPair(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if privA.Equals(privB) {
			t.Fatal("different keys were equal")
		}
	})
}

// TestPublicKeyEquals tests the Equals method for public keys.
func TestPublicKeyEqualsBJJ(t *testing.T) {
	_, pubA, err := GenerateBJJKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Self equals", func(t *testing.T) {
		if !pubA.Equals(pubA) {
			t.Fatal("public key not equal to itself")
		}
	})

	t.Run("Same key equals", func(t *testing.T) {
		pubB, err := BJJPublicKeyFromPubKey(*pubA.(*BJJPublicKey).pub)
		if err != nil {
			t.Fatal(err)
		}
		if !pubA.Equals(pubB) {
			t.Fatal("same key did not equal")
		}
	})

	t.Run("Different key not equals", func(t *testing.T) {
		_, pubB, err := GenerateBJJKeyPair(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if pubA.Equals(pubB) {
			t.Fatal("different keys were equal")
		}
	})
}

// TestKeyType tests the KeyType method.
func TestKeyTypeBJJ(t *testing.T) {
	priv, pub, err := GenerateBJJKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if priv.Type() != pb.KeyType_Babyjubjub {
		t.Fatal("private key type was incorrect")
	}

	if pub.Type() != pb.KeyType_Babyjubjub {
		t.Fatal("public key type was incorrect")
	}
}

// TestKeyGenerators tests the key generation methods.
func TestKeyGeneratorsBJJ(t *testing.T) {
	t.Run("GenerateBJJKeyPair", func(t *testing.T) {
		priv, pub, err := GenerateBJJKeyPair(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if priv == nil || pub == nil {
			t.Fatal("key pair generation failed")
		}
	})

	t.Run("BJJKeyPairFromKey", func(t *testing.T) {
		privKey := new(babyjub.PrivateKey)
		if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
			t.Fatal(err)
		}
		priv, pub, err := BJJKeyPairFromKey(privKey)
		if err != nil {
			t.Fatal(err)
		}
		if priv == nil || pub == nil {
			t.Fatal("key pair from key generation failed")
		}
	})

	t.Run("BJJPublicKeyFromPubKey", func(t *testing.T) {
		privKey := new(babyjub.PrivateKey)
		if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
			t.Fatal(err)
		}
		pubKey := privKey.Public()
		pub, err := BJJPublicKeyFromPubKey(*pubKey)
		if err != nil {
			t.Fatal(err)
		}
		if pub == nil {
			t.Fatal("public key from pub key generation failed")
		}
	})
}

// TestMarshalUnmarshal tests marshaling and unmarshaling with raw key data.
func TestMarshalUnmarshalBJJ(t *testing.T) {
	priv, pub, err := GenerateBJJKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("private", func(t *testing.T) {
		raw, err := priv.Raw()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalBJJPrivateKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !restored.Equals(priv) {
			t.Fatal("unmarshaled key not equal to original")
		}
	})

	t.Run("public", func(t *testing.T) {
		raw, err := pub.Raw()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalBJJPublicKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !restored.Equals(pub) {
			t.Fatal("unmarshaled key not equal to original")
		}
	})
}
