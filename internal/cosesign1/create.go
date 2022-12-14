package cosesign1

import (
	"crypto/rand"
	"fmt"

	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/veraison/go-cose"
)

func pem2der(chainPem []byte) []byte {
	block, rest := pem.Decode(chainPem)
	if block != nil && block.Bytes != nil {
		r := block.Bytes

		for len(rest) != 0 {
			block, rest = pem.Decode(rest)
			if block != nil && block.Bytes != nil {
				r = append(r, block.Bytes...)
			}
		}
		return r
	}
	return nil
}

// CreateCoseSign1 returns a COSE Sign1 document as an array of bytes.
//
//		payloadBlob is the payload to be placed inside the envelope.
//		issuer is an arbitary string, placed in the protected header along with the other strings. Typically this might be a did:x509 that identifies the party that published the document.
//	 feed is another abribitary string. Typically it is an identier for the object stored in the document.
//		contentType is a string to describe the payload content, eg application/rego or application/json
//	 chainPem is an array of bytes containing the certificate chain. That chain is stored and used by a receiver to validate the signature. The leaf cert must match the private key.
//	 keyPem is an array of bytes (PEM format) containing the private key used to sign the document.
func CreateCoseSign1(payloadBlob []byte, issuer string, feed string, contentType string, chainPem []byte, keyPem []byte, saltType string, algo cose.Algorithm) (result []byte, err error) {
	var signingKey any
	var keyDer *pem.Block
	keyDer, _ = pem.Decode(keyPem) // discard remaining bytes
	if keyDer == nil {
		return nil, fmt.Errorf("failed to find key in PEM")
	}
	var keyBytes = keyDer.Bytes

	// try parsing the various likely key types in turn
	signingKey, err = x509.ParseECPrivateKey(keyBytes)
	if err == nil {
		logrus.Debugf("parsed EC signing (private) key %q\n", signingKey)
	}

	if err != nil {
		signingKey, err = x509.ParsePKCS8PrivateKey(keyBytes)
		if err == nil {
			logrus.Debugf("parsed PKCS8 signing (private) key %q\n", signingKey)
		}
	}

	if err != nil {
		signingKey, err = x509.ParsePKCS1PrivateKey(keyBytes)
		if err == nil {
			logrus.Debugf("parsed PKCS1 signing (private) key %q\n", signingKey)
		}
	}

	if err != nil {
		logrus.Debug("failed to decode a key, error = " + err.Error())
		return nil, err
	}

	chainDER := pem2der(chainPem)
	if chainDER == nil {
		return nil, fmt.Errorf("failed to parse chainPem")
	}

	var chainCerts []*x509.Certificate
	chainCerts, err = x509.ParseCertificates(chainDER)

	if err == nil {
		logrus.Debugf("parsed cert chain for leaf: %v\n", *chainCerts[0])
	} else {
		logrus.Debug("cert parsing failed - " + err.Error())
		return nil, err
	}

	chainDERArray := make([][]byte, len(chainCerts))
	for i, cert := range chainCerts {
		chainDERArray[i] = cert.Raw
	}

	var saltReader io.Reader
	if saltType == "rand" {
		saltReader = rand.Reader
	} else {
		saltReader = NewFixedReader(0)
	}

	cryptoSigner, ok := signingKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("signingKey must be of type crypto.Signer")
	}

	var signer cose.Signer
	signer, err = cose.NewSigner(algo, cryptoSigner)
	if err != nil {
		logrus.Debug("cose.NewSigner err = " + err.Error())
		return nil, err
	}

	// See https://www.iana.org/assignments/cose/cose.xhtml#:~:text=COSE%20Header%20Parameters%20%20%20%20Name%20,algorithm%20to%20use%20%2019%20more%20rows

	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   algo,
			cose.HeaderLabelContentType: contentType,
			cose.HeaderLabelX5Chain:     chainDERArray,
		},
	}

	// see https://ietf-scitt.github.io/draft-birkholz-scitt-architecture/draft-birkholz-scitt-architecture.html#name-envelope-and-claim-format
	// Use of strings here to match PRSS COSE Sign1 service

	if len(issuer) > 0 {
		headers.Protected["iss"] = issuer
	}
	if len(feed) > 0 {
		headers.Protected["feed"] = feed
	}

	result, err = cose.Sign1(saltReader, signer, headers, payloadBlob, nil)
	if err != nil {
		logrus.Debug("cose.Sign1 creation failed\n" + err.Error())
		return nil, err
	}

	return result, nil
}
