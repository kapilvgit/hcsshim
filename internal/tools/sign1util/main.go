package main

import (
	"flag"
	"os"

	"log"

	"github.com/Microsoft/hcsshim/pkg/cosesign1"
)

func checkCoseSign1(inputFilename string, optionalPubKeyFilename string, requireKnownAuthority bool, verbose bool) (map[string]string, error) {
	var coseBlob []byte = cosesign1.ReadBlob(inputFilename)
	var optionalPubKeyPEM []byte
	if optionalPubKeyFilename != "" {
		optionalPubKeyPEM = cosesign1.ReadBlob(optionalPubKeyFilename)
	}
	var results map[string]string
	var err error
	results, err = cosesign1.UnpackAndValidateCOSE1CertChain(coseBlob, optionalPubKeyPEM, requireKnownAuthority, verbose)
	if err != nil {
		log.Print("checkCoseSign1 failed - " + err.Error())
	} else if len(results) == 0 {
		log.Print("checkCoseSign1 did not pass, result map is empty.")
	} else {
		log.Print("checkCoseSign1 passed:")
		log.Printf("iss:\n%s\n", results["iss"])
		log.Printf("pubkey:\n%s\n", results["pubkey"])
		log.Printf("content type:\n%s\n", results["cty"])
		log.Printf("payload:\n%s\n", results["payload"])
	}
	return results, err
}

// example scitt usage to try tro match
// scitt sign --claims <fragment>.rego --content-type application/unknown+json --did-doc ~/keys/did.json --key ~/keys/key.pem --out <fragment>.cose
func main() {
	var payloadFilename string
	var contentType string
	var chainFilename string
	var keyFilename string
	var outputFilename string
	var outputKeyFilename string
	var inputFilename string
	var saltType string
	var requireKNownAuthority bool
	var verbose bool
	var algo string

	createCmd := flag.NewFlagSet("create", flag.ExitOnError)

	createCmd.StringVar(&payloadFilename, "claims", "fragment.rego", "filename of payload")
	createCmd.StringVar(&contentType, "content-type", "application/unknown+json", "content type, eg appliation/json")
	createCmd.StringVar(&chainFilename, "cert", "pubcert.pem", "key or cert file to use (pem)")
	createCmd.StringVar(&keyFilename, "key", "key.pem", "key to sign with (private key of the leaf of the chain)")
	createCmd.StringVar(&outputFilename, "out", "out.cose", "output file")
	createCmd.StringVar(&outputKeyFilename, "keyout", "out.pem", "output file")
	createCmd.StringVar(&saltType, "salt", "zero", "rand or zero")
	createCmd.StringVar(&algo, "algo", "PS384", "PS256, PS384 etc")
	createCmd.BoolVar(&verbose, "verbose", false, "verbose output")

	checkCmd := flag.NewFlagSet("check", flag.ExitOnError)

	checkCmd.StringVar(&inputFilename, "in", "input.cose", "input file")
	checkCmd.StringVar(&keyFilename, "pub", "", "input public key (PEM)")
	checkCmd.BoolVar(&requireKNownAuthority, "requireKNownAuthority", false, "false => allow chain validation to fail")
	checkCmd.BoolVar(&verbose, "verbose", false, "verbose output")

	printCmd := flag.NewFlagSet("print", flag.ExitOnError)

	printCmd.StringVar(&inputFilename, "in", "input.cose", "input file")

	leafKeyCmd := flag.NewFlagSet("leafkey", flag.ExitOnError)

	leafKeyCmd.StringVar(&inputFilename, "in", "input.cose", "input file")
	leafKeyCmd.StringVar(&outputFilename, "out", "leafkey.pem", "output file")
	leafKeyCmd.BoolVar(&verbose, "verbose", false, "verbose output")

	if len(os.Args) > 1 {
		var action string = os.Args[1]
		switch action {
		case "create":
			createCmd.Parse(os.Args[2:])
			algorithm, err := cosesign1.StringToAlgorithm(algo)
			var raw []byte
			if err == nil {
				raw, err = cosesign1.CreateCoseSign1(payloadFilename, contentType, chainFilename, keyFilename, saltType, algorithm, verbose)
			}

			if err != nil {
				log.Print("failed create: " + err.Error())
			} else {
				if len(outputFilename) > 0 {
					err = cosesign1.WriteBlob(outputFilename, raw)
					if err != nil {
						log.Printf("writeBlob failed for %s\n", outputFilename)
					}
				}
			}

		case "check":
			checkCmd.Parse(os.Args[2:])
			_, err := checkCoseSign1(inputFilename, keyFilename, requireKNownAuthority, verbose)
			if err != nil {
				log.Print("failed check: " + err.Error())
			}

		case "print":
			printCmd.Parse(os.Args[2:])
			_, err := checkCoseSign1(inputFilename, "", false, true)
			if err != nil {
				log.Print("failed print: " + err.Error())
			}

		case "leafkey":
			leafKeyCmd.Parse(os.Args[2:])
			results, err := checkCoseSign1(inputFilename, "", false, verbose)
			if err == nil {
				cosesign1.WriteString(outputFilename, results["pubkey"])
			}
		default:
			os.Stderr.WriteString("Usage: sign1util [create|check|print|leafkey] -h\n")
		}

	} else {
		os.Stderr.WriteString("Usage: sign1util [create|check|print|leafkey] -h\n")
	}
}
