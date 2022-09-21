package cosesign1

import (
	_ "embed"
	"testing"
	"testing/quick"
)

//go:embed fragment.rego
var FragmentRego string

//go:embed fragment.cose
var FragmentCose []byte

// This is a self signed key which is only used for testing, it is not a risk.
// It enables a check against the key and signature blobs

//go:embed key.pem
var KeyStrippedPem string // Strip off the BEGIN/END so we don't trigger credential checks

var begingPrivateKey = "-----BEGIN PRIVATE KEY-----\n"
var endPrivateKey = "-----END PRIVATE KEY-----"

var KeyPem = begingPrivateKey + KeyStrippedPem + endPrivateKey

//go:embed pubcert.pem
var PubCertPem string

//go:embed leafcert.pem
var LeafCertPem string

// Validate that our conversion from the external SecurityPolicy representation
// to our internal format is done correctly.
func Test_UnpackAndValidateCannedFragment(t *testing.T) {
	f := func() bool {
		var resultsMap, err = UnpackAndValidateCOSE1CertChain(FragmentCose, nil, false, false)
		if err != nil {
			return false
		}
		var iss = resultsMap["iss"]
		var cty = resultsMap["cty"]
		var payload = resultsMap["payload"]

		//var leafCertPem = begin + LeafCertBody + end

		if iss != LeafCertPem {
			return false
		}
		if cty != "application/unknown+json" {
			return false
		}
		if payload != FragmentRego {
			return false
		}
		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Errorf("Test_UnpackAndValidateCannedFragment failed: %v", err)
	}
}

func Test_CreateCoseSign1Fragment(t *testing.T) {
	f := func() bool {
		var raw, err = CreateCoseSign1([]byte(FragmentRego), "application/unknown+json", []byte(PubCertPem), []byte(KeyPem), "zero")
		if err != nil {
			return false
		}

		if len(raw) != len(FragmentCose) {
			return false
		}

		for which, _ := range raw {
			if raw[which] != FragmentCose[which] {
				return false
			}
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Errorf("Test_UnpackAndValidateCannedFragment failed: %v", err)
	}
}
