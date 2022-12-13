package main

import (
	"flag"

	"os"

	"github.com/sirupsen/logrus"

	"github.com/Microsoft/hcsshim/internal/cosesign1"
	didx509resolver "github.com/Microsoft/hcsshim/internal/did-x509-resolver"
)

func checkCoseSign1(inputFilename string, chainFilename string, didString string, verbose bool) (*cosesign1.UnpackedCoseSign1, error) {
	if verbose == true {
		logrus.SetLevel(logrus.DebugLevel)
	}
	coseBlob := cosesign1.ReadBlob(inputFilename)

	var chainPEM []byte
	var chainPEMString string
	if chainFilename != "" {
		chainPEM = cosesign1.ReadBlob(chainFilename)
		chainPEMString = string(chainPEM[:])
	}

	var unpacked *cosesign1.UnpackedCoseSign1
	var err error
	unpacked, err = cosesign1.UnpackAndValidateCOSE1CertChain(coseBlob)
	if err != nil {
		logrus.Print("checkCoseSign1 failed - " + err.Error())
		return nil, err
	}

	logrus.Print("checkCoseSign1 passed:")
	if verbose {
		logrus.Printf("iss: %s", unpacked.Issuer)
		logrus.Printf("feed: %s", unpacked.Feed)
		logrus.Printf("cty: %s", unpacked.ContentType)
		logrus.Printf("pubkey: %s", unpacked.Pubkey)
		logrus.Printf("pubcert: %s", unpacked.Pubcert)
		logrus.Printf("payload:\n%s\n", string(unpacked.Payload[:]))
	}
	if len(didString) > 0 {
		if len(chainPEMString) == 0 {
			chainPEMString = unpacked.ChainPem
		}
		didDoc, err := didx509resolver.Resolve(chainPEMString, didString, true)
		if err == nil {
			logrus.Printf("DID resolvers passed:\n%s\n", didDoc)
		} else {
			logrus.Printf("DID resolvers failed: err: %s doc:\n%s\n", err.Error(), didDoc)
		}
	}

	return unpacked, err
}

func createCoseSign1(payloadFilename string, issuer string, feed string, contentType string, chainFilename string, keyFilename string, saltType string, algo string, verbose bool) ([]byte, error) {
	if verbose == true {
		logrus.SetLevel(logrus.DebugLevel)
	}
	payloadBlob := cosesign1.ReadBlob(payloadFilename)
	keyPem := cosesign1.ReadBlob(keyFilename)
	chainPem := cosesign1.ReadBlob(chainFilename)
	algorithm, err := cosesign1.StringToAlgorithm(algo)
	if err != nil {
		return nil, err
	}

	return cosesign1.CreateCoseSign1(payloadBlob, issuer, feed, contentType, chainPem, keyPem, saltType, algorithm)
}

func main() {
	var payloadFilename string
	var contentType string
	var chainFilename string
	var keyFilename string
	var outputFilename string
	var outputCertFilename string
	var outputKeyFilename string
	var inputFilename string
	var saltType string
	var verbose bool
	var algo string
	var feed string
	var issuer string
	var didPolicy string
	var didString string
	var didFingerprintIndex int
	var didFingerprintAlgorithm string

	var formatter = logrus.TextFormatter{
		DisableColors:    true,
		FullTimestamp:    true,
		DisableQuote:     true,
		DisableTimestamp: true,
	}

	logrus.SetFormatter(&formatter)

	if len(os.Args) > 1 {
		action := os.Args[1]
		switch action {
		case "create":
			createCmd := flag.NewFlagSet("create", flag.ExitOnError)
			createCmd.StringVar(&payloadFilename, "claims", "fragment.rego", "filename of payload")
			createCmd.StringVar(&contentType, "content-type", "application/unknown+json", "content type, eg appliation/json")
			createCmd.StringVar(&chainFilename, "chain", "chain.pem", "key or cert file to use (pem)")
			createCmd.StringVar(&keyFilename, "key", "key.pem", "key to sign with (private key of the leaf of the chain)")
			createCmd.StringVar(&outputFilename, "out", "out.cose", "output file")
			createCmd.StringVar(&saltType, "salt", "rand", "rand or zero")
			createCmd.StringVar(&algo, "algo", "ES384", "PS256, PS384 etc")
			createCmd.StringVar(&issuer, "issuer", "", "the party making the claims") // see https://ietf-scitt.github.io/draft-birkholz-scitt-architecture/draft-birkholz-scitt-architecture.html#name-terminology
			createCmd.StringVar(&feed, "feed", "", "identifier for an artifact within the scope of an issuer")
			createCmd.BoolVar(&verbose, "verbose", false, "verbose output")

			err := createCmd.Parse(os.Args[2:])
			if err == nil {
				var raw []byte
				if err == nil {
					raw, err = createCoseSign1(payloadFilename, issuer, feed, contentType, chainFilename, keyFilename, saltType, algo, verbose)
				}

				if err != nil {
					logrus.Print("failed create: " + err.Error())
				} else {
					if len(outputFilename) > 0 {
						err = cosesign1.WriteBlob(outputFilename, raw)
						if err != nil {
							logrus.Printf("writeBlob failed for %s\n", outputFilename)
						}
					}
				}
			} else {
				logrus.Print("args parse failed: " + err.Error())
			}

		case "check":
			checkCmd := flag.NewFlagSet("check", flag.ExitOnError)
			checkCmd.StringVar(&inputFilename, "in", "input.cose", "input file")
			checkCmd.StringVar(&chainFilename, "chain", "chain.pem", "key or cert file to use (pem)")
			checkCmd.StringVar(&didString, "did", "", "DID x509 string to resolve against cert chain")
			checkCmd.BoolVar(&verbose, "verbose", false, "verbose output")

			err := checkCmd.Parse(os.Args[2:])
			if err == nil {
				_, err := checkCoseSign1(inputFilename, chainFilename, didString, verbose)
				if err != nil {
					logrus.Print("failed check: " + err.Error())
				}
			} else {
				logrus.Print("args parse failed: " + err.Error())
			}

		case "print":
			printCmd := flag.NewFlagSet("print", flag.ExitOnError)
			printCmd.StringVar(&inputFilename, "in", "input.cose", "input file")

			err := printCmd.Parse(os.Args[2:])
			if err == nil {
				_, err := checkCoseSign1(inputFilename, chainFilename, didString, true)
				if err != nil {
					logrus.Print("failed print: " + err.Error())
				}
			} else {
				logrus.Print("args parse failed: " + err.Error())
			}

		case "leaf":
			leafCmd := flag.NewFlagSet("leaf", flag.ExitOnError)
			leafCmd.StringVar(&inputFilename, "in", "input.cose", "input file")
			leafCmd.StringVar(&outputKeyFilename, "keyout", "leafkey.pem", "leaf key output file")
			leafCmd.StringVar(&outputCertFilename, "certout", "leafcert.pem", "leaf cert output file")
			leafCmd.BoolVar(&verbose, "verbose", false, "verbose output")

			err := leafCmd.Parse(os.Args[2:])
			if err == nil {
				unpacked, err := checkCoseSign1(inputFilename, chainFilename, didString, verbose)
				if err == nil {
					err = cosesign1.WriteString(outputKeyFilename, unpacked.Pubkey)
					if err != nil {
						logrus.Printf("writing the leaf pub key to %s failed: %s", outputKeyFilename, err.Error())
					} else {
						err = cosesign1.WriteString(outputCertFilename, unpacked.Pubcert)
						if err != nil {
							logrus.Printf("writing the leaf cert to %s failed: %s", outputCertFilename, err.Error())
						}
					}
				} else {
					logrus.Printf("reading the COSE Sign1 from %s failed: %s", inputFilename, err.Error())
				}
			} else {
				logrus.Print("args parse failed: " + err.Error())
			}

		case "did:x509":
			didX509Cmd := flag.NewFlagSet("did:x509", flag.ExitOnError)
			didX509Cmd.StringVar(&didFingerprintAlgorithm, "fingerprint-algorithm", "sha256", "hash algorithm for certificate fingerprints")
			didX509Cmd.StringVar(&chainFilename, "chain", "", "certificate chain to use (pem)")
			didX509Cmd.IntVar(&didFingerprintIndex, "i", 1, "index of the certificate fingerprint in the chain")
			didX509Cmd.StringVar(&didPolicy, "policy", "cn", "did:509 policy (cn/eku/custom)")
			didX509Cmd.BoolVar(&verbose, "verbose", false, "verbose output")
			didX509Cmd.StringVar(&inputFilename, "in", "", "input file")

			err := didX509Cmd.Parse(os.Args[2:])
			var chainPEM string
			if err == nil {
				if len(chainFilename) > 0 {
					chainPEM = string(cosesign1.ReadBlob("chain.pem"))
				}
				if len(inputFilename) > 0 {
					if len(chainFilename) > 0 {
						logrus.Print("cannot specify chain with cose file - it comes from the chain in the file")
						break
					}
					unpacked, err := checkCoseSign1(inputFilename, "", "", true)
					if err != nil {
						logrus.Print("error: " + err.Error())
						break
					}

					chainPEM = unpacked.ChainPem
				}
				r, err := cosesign1.MakeDidX509(didFingerprintAlgorithm, didFingerprintIndex, chainPEM, didPolicy, verbose)
				if err != nil {
					logrus.Print("error: " + err.Error())
				} else {
					print(r + "\n")
				}
			} else {
				logrus.Print("args parse failed: " + err.Error())
			}

		case "chain":
			chainCmd := flag.NewFlagSet("chain", flag.ExitOnError)
			chainCmd.StringVar(&inputFilename, "in", "input.cose", "input file")

			err := chainCmd.Parse(os.Args[2:])
			if err == nil {
				err := cosesign1.PrintChain(inputFilename)
				if err != nil {
					logrus.Print("error: " + err.Error())
				}
			}

		default:
			os.Stderr.WriteString("Usage: sign1util [create|check|print|leafkey|did:x509] -h\n")
		}

	} else {
		os.Stderr.WriteString("Usage: sign1util [create|check|print|leafkey|did:x509] -h\n")
	}
}
