package main

import (
	"encoding/hex"
	"syscall/js"

	mcrypto "github.com/athanorlabs/atomic-swap/crypto/monero"
	csecp256k1 "github.com/athanorlabs/atomic-swap/crypto/secp256k1"
	"github.com/athanorlabs/go-dleq"
	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/secp256k1"
	dsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func main() {
	js.Global().Set("generateSecretForCurves", js.FuncOf(jsGenerateSecretForCurves))
	js.Global().Set("newProof", js.FuncOf(jsNewProof))
	js.Global().Set("verifyProof", js.FuncOf(jsVerifyProof))

	select {} //Keep WASM runtime alive
}

// ==== JS Wrappers ====
// Wrapper for generateSecretForCurves
func jsGenerateSecretForCurves(this js.Value, args []js.Value) any {
	secret := generateSecretForCurves()
	return hex.EncodeToString(secret[:])
}

// Wrapper for NewProof
func jsNewProof(this js.Value, args []js.Value) any {
	if len(args) != 1 {
		return "expected 1 argument: secret (hex string)"
	}
	secretHex := args[0].String()
	secretBytes, err := hex.DecodeString(secretHex)
	if err != nil || len(secretBytes) != 32 {
		return "invalid secret format (expected 32-byte hex)"
	}
	var secret [32]byte
	copy(secret[:], secretBytes)
	proofBytes := NewProof(secret)
	return hex.EncodeToString(proofBytes)
}

// Wrapper for Verify
func jsVerifyProof(this js.Value, args []js.Value) any {
	if len(args) != 1 {
		return "expected 1 argument: proof (hex string)"
	}

	proofHex := args[0].String()
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return "invalid proof format (hex string expected)"
	}
	ethereumPubkey, moneroPubkey := Verify(proofBytes)

	result := map[string]any{
		"secp256k1Pub": ethereumPubkey,
		"ed25519Pub":   moneroPubkey,
	}
	return js.ValueOf(result)
}

// === Internal Go Logic ===

func generateSecretForCurves() [32]byte {
	curveA := secp256k1.NewCurve()
	curveB := ed25519.NewCurve()
	x, err := dleq.GenerateSecretForCurves(curveA, curveB)
	if err != nil {
		panic(err)
	}
	return x
}

func NewProof(x [32]byte) []byte {
	curveA := secp256k1.NewCurve()
	curveB := ed25519.NewCurve()
	proof, err := dleq.NewProof(curveA, curveB, x)
	if err != nil {
		panic(err)
	}
	return proof.Serialize()
}

type VerifyResult struct {
	ed25519Pub   string
	secp256k1Pub string
}

func Verify(serialized_proof []byte) (string, string) {
	var proof dleq.Proof

	curveA := secp256k1.NewCurve()
	curveB := ed25519.NewCurve()

	proof.Deserialize(curveA, curveB, serialized_proof)

	err := proof.Verify(curveA, curveB)
	if err != nil {

		panic(err)
	}

	secpPub, err := dsecp256k1.ParsePubKey(proof.CommitmentA.Encode())
	if err != nil {

		panic(err)
	}

	secp256k1Pub := csecp256k1.NewPublicKeyFromBigInt(secpPub.X(), secpPub.Y())

	ed25519Pub, err := mcrypto.NewPublicKeyFromBytes(proof.CommitmentB.Encode())
	if err != nil {

		panic(err)
	}

	return secp256k1Pub.String(), ed25519Pub.String()
}
