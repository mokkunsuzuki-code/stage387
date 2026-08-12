package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func readFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"FAIL: cannot read %s: %v\n",
			path,
			err,
		)
		os.Exit(1)
	}
	return data
}

func main() {
	publicKeyPath := flag.String(
		"public-key-raw",
		"",
		"Path to raw ML-DSA-65 public key",
	)

	signaturePath := flag.String(
		"signature",
		"",
		"Path to ML-DSA-65 signature",
	)

	messagePath := flag.String(
		"message",
		"",
		"Path to signed message",
	)

	context := flag.String(
		"context",
		"",
		"ML-DSA context string",
	)

	flag.Parse()

	if *publicKeyPath == "" ||
		*signaturePath == "" ||
		*messagePath == "" {
		fmt.Fprintln(
			os.Stderr,
			"FAIL: required input path missing",
		)
		os.Exit(1)
	}

	rawPublicKey := readFile(
		*publicKeyPath,
	)

	signature := readFile(
		*signaturePath,
	)

	message := readFile(
		*messagePath,
	)

	fmt.Println(
		"implementation = Cloudflare CIRCL",
	)

	fmt.Println(
		"algorithm = ML-DSA-65",
	)

	fmt.Println(
		"raw_public_key_size =",
		len(rawPublicKey),
	)

	fmt.Println(
		"signature_size =",
		len(signature),
	)

	fmt.Println(
		"message_size =",
		len(message),
	)

	fmt.Println(
		"context =",
		*context,
	)

	if len(rawPublicKey) != mldsa65.PublicKeySize {
		fmt.Fprintln(
			os.Stderr,
			"FAIL: ML-DSA-65 public-key size mismatch",
		)
		os.Exit(1)
	}

	if len(signature) != mldsa65.SignatureSize {
		fmt.Fprintln(
			os.Stderr,
			"FAIL: ML-DSA-65 signature size mismatch",
		)
		os.Exit(1)
	}

	var publicKey mldsa65.PublicKey

	err := publicKey.UnmarshalBinary(
		rawPublicKey,
	)

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"FAIL: CIRCL public-key decoding failed:",
			err,
		)
		os.Exit(1)
	}

	fmt.Println(
		"public_key_decoded = true",
	)

	verified := mldsa65.Verify(
		&publicKey,
		message,
		[]byte(*context),
		signature,
	)

	fmt.Println(
		"circl_mldsa65_verified =",
		verified,
	)

	if !verified {
		fmt.Fprintln(
			os.Stderr,
			"FAIL: CIRCL ML-DSA-65 verification failed",
		)
		os.Exit(1)
	}

	fmt.Println(
		"PASS: CIRCL independently verified the historical Stage375 ML-DSA-65 signature",
	)
}
