package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
)

func main() {
	// Unmarshal the report into a SignedAttestationReport object
	file, _ := os.Open("report.bin")
	report, err := verifier.NewSignedAttestationReport(bufio.NewReader(file))
	if err != nil {
		panic(err)
	}

	// Validate the report's root of trust and PCR values
	expectedValues := verifier.PCRMap{
		0: "000000",
		1: "000001",
	}

	if err = verifier.Validate(report, expectedValues); err != nil {
		panic(err)
	}

	fmt.Println("Report is valid!")

	// Access the user data
	fmt.Printf("Recovered user data: %s\n", report.Document.UserData)
}
