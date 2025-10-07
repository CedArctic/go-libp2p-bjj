package crypto

import (
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"github.com/iden3/go-iden3-crypto/v2/babyjub"
	bjj_constants "github.com/iden3/go-iden3-crypto/v2/constants"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/internal/catch"
)

// BJJPrivateKey is an implementation of a Babyjubjub private key
type BJJPrivateKey struct {
	priv *babyjub.PrivateKey
}

// BJJPublicKey is an implementation of a Babyjubjub public key
type BJJPublicKey struct {
	pub *babyjub.PublicKey
}

// GenerateBJJKeyPair generates a new Babyjubjub private and public key
func GenerateBJJKeyPair(src io.Reader) (PrivKey, PubKey, error) {
	// Generate 32 random bytes
	var buf [32]byte
	_, err := io.ReadFull(src, buf[:])
	if err != nil {
		return nil, nil, err
	}

	// Convert random bytes to scalar sk
	sk := new(big.Int).SetBytes(buf[:])
	L := babyjub.SubOrder

	// Reduce modulo the subgroup order
	sk.Mod(sk, L)
	if sk.Sign() == 0 {
		sk.SetInt64(1)
	}

	// Create a BabyJubJub private scalar
	skScalar := babyjub.NewPrivKeyScalar(sk)

	// Derive the public key using the existing .Public() method
	pubKey := skScalar.Public()

	// Wrap into the expected key types
	privKey := new(babyjub.PrivateKey)
	copy(privKey[:], buf[:])

	return &BJJPrivateKey{priv: privKey}, &BJJPublicKey{pub: pubKey}, nil
}

// BJJKeyPairFromScalar creates a keypair from a given scalar sk.
func BJJKeyPairFromScalar(sk *big.Int) (PrivKey, PubKey, error) {
	L := babyjub.SubOrder
	sk.Mod(sk, L)
	if sk.Sign() == 0 {
		sk.SetInt64(1)
	}

	skScalar := babyjub.NewPrivKeyScalar(sk)
	pubKey := skScalar.Public()

	privKey := new(babyjub.PrivateKey)
	skBytes := sk.Bytes()
	copy(privKey[32-len(skBytes):], skBytes) // right-align for big-endian

	return &BJJPrivateKey{priv: privKey}, &BJJPublicKey{pub: pubKey}, nil
}

// BJJKeyPairFromKey generates a new Babyjubjub private and public key from an input private key
func BJJKeyPairFromKey(priv *babyjub.PrivateKey) (PrivKey, PubKey, error) {
	if priv == nil {
		return nil, nil, ErrNilPrivateKey
	}

	// Convert raw bytes to scalar
	sk := new(big.Int).SetBytes(priv[:])
	L := babyjub.SubOrder
	sk.Mod(sk, L)
	if sk.Sign() == 0 {
		sk.SetInt64(1)
	}

	// Create BabyJubJub private scalar and derive public key
	skScalar := babyjub.NewPrivKeyScalar(sk)
	pubKey := skScalar.Public()

	return &BJJPrivateKey{priv}, &BJJPublicKey{pubKey}, nil
}

// BJJPublicKeyFromPubKey generates a new Babyjubjub public key from an input public key
func BJJPublicKeyFromPubKey(pub babyjub.PublicKey) (PubKey, error) {
	return &BJJPublicKey{pub: &pub}, nil
}

// MarshalBJJPrivateKey returns bytes from a private key
func MarshalBJJPrivateKey(ePriv BJJPrivateKey) (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "Babyjubjub private-key marshal") }()
	return ePriv.Raw()
}

// MarshalBJJPublicKey returns bytes from a public key
func MarshalBJJPublicKey(ePub BJJPublicKey) (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "Babyjubjub public-key marshal") }()
	return ePub.Raw()
}

// UnmarshalBJJPrivateKey returns a private key from bytes
func UnmarshalBJJPrivateKey(data []byte) (res PrivKey, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "Babyjubjub private-key unmarshal") }()
	if len(data) > 32 {
		return nil, errors.New("Invalid babyjubjub private key length")
	}
	priv := new(babyjub.PrivateKey)
	copy(priv[:], data)
	return &BJJPrivateKey{priv}, nil
}

// UnmarshalBJJPublicKey returns the public key from bytes
func UnmarshalBJJPublicKey(data []byte) (key PubKey, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "Babyjubjub public-key unmarshal") }()

	pub_c := new(babyjub.PublicKeyComp)
	copy(pub_c[:], data)

	pub, err := pub_c.Decompress()
	if err != nil {
		return nil, err
	}

	return &BJJPublicKey{pub}, nil
}

// Type returns the key type
func (ePriv *BJJPrivateKey) Type() pb.KeyType {
	return pb.KeyType_Babyjubjub
}

// Raw returns bytes from a private key
func (ePriv *BJJPrivateKey) Raw() (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "Babyjubjub private-key marshal") }()
	out := make([]byte, len(ePriv.priv))
	copy(out, ePriv.priv[:])
	return out, nil
}

// Equals compares two private keys
func (ePriv *BJJPrivateKey) Equals(o Key) bool {
	return basicEquals(ePriv, o)
}

// Sign returns the signature of the input data
func (ePriv *BJJPrivateKey) Sign(data []byte) (sig []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "Babyjubjub signing") }()
	hash := sha256.Sum256(data)
	hashBigInt := new(big.Int)
	hashBigInt.SetBytes(hash[:])

	// Perform a modular reduction
	hashBigInt.Mod(hashBigInt, bjj_constants.Q)

	pos_sig, err := ePriv.priv.SignPoseidon(hashBigInt)
	if err != nil {
		return nil, err
	}
	comp_sig := pos_sig.Compress()
	sig = comp_sig[:]
	return sig, nil
}

// GetPublic returns a public key
func (ePriv *BJJPrivateKey) GetPublic() PubKey {
	// Convert the private key bytes into a scalar
	sk := new(big.Int).SetBytes(ePriv.priv[:])
	L := babyjub.SubOrder

	// Reduce modulo the subgroup order and ensure nonzero
	sk.Mod(sk, L)
	if sk.Sign() == 0 {
		sk.SetInt64(1)
	}

	// Derive public key from scalar
	skScalar := babyjub.NewPrivKeyScalar(sk)
	pubKey := skScalar.Public()

	return &BJJPublicKey{pubKey}
}

// Type returns the key type
func (ePub *BJJPublicKey) Type() pb.KeyType {
	return pb.KeyType_Babyjubjub
}

// Raw returns bytes from a public key
func (ePub *BJJPublicKey) Raw() (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "Babyjubjub public-key marshal") }()
	compressed := ePub.pub.Compress()
	return compressed[:], nil
}

// Type returns the key type
func (ePub *BJJPublicKey) GetXY() (big.Int, big.Int) {
	return *ePub.pub.X, *ePub.pub.Y
}

// Equals compares to public keys
func (ePub *BJJPublicKey) Equals(o Key) bool {
	return basicEquals(ePub, o)
}

// Verify compares data to a signature
func (ePub *BJJPublicKey) Verify(data, sigBytes []byte) (success bool, err error) {
	defer func() {
		catch.HandlePanic(recover(), &err, "Babyjubjub signature verification")

		// Just to be extra paranoid.
		if err != nil {
			success = false
		}
	}()

	// Decompress signature
	sig := new(babyjub.Signature)
	_, err = sig.Decompress([64]byte(sigBytes[:64]))
	if err != nil {
		return false, err
	}
	// Calculate hash big.Int
	hash := sha256.Sum256(data)
	hashBigInt := new(big.Int)
	hashBigInt.SetBytes(hash[:])
	// Perform a modular reduction
	hashBigInt.Mod(hashBigInt, bjj_constants.Q)
	// Verify signature
	err = ePub.pub.VerifyPoseidon(hashBigInt, sig)
	if err == babyjub.ErrVerifyPoseidonFailed {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
