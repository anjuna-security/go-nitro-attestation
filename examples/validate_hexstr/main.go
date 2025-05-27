package main

import (
	"fmt"
	"os"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
)

func main() {
	// Unmarshal the report into a SignedAttestationReport object
	file, _ := os.Open("report.bin")
	report, err := verifier.NewSignedAttestationReport(file)
	if err != nil {
		panic(err)
	}

	// Validate the report's root of trust
	if err = verifier.Validate(report, nil); err != nil {
		panic(err)
	}

	// Access the PCR values as hex strings
	hexPCRs := verifier.ConvertPCRsToHex(report.Document.PCRs)

	// Validate the PCR values with any custom logic you want
	if hexPCRs[0] != "000000" {
		panic("PCR0 value is not as expected")
	}
	if hexPCRs[1] != "000001" {
		panic("PCR1 value is not as expected")
	}

	fmt.Println("Report is valid!")

	// Access the user data
	fmt.Printf("Recovered user data: %s\n", report.Document.UserData)
}
