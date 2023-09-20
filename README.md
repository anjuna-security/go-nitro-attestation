# Anjuna Nitro Attestation

This repo defines the needed data structures and packages to:

1. Programatically generate an AWS Nitro Attestation Report from an Anjuna Nitro Enclave
1. Validate an AWS Nitro Attestation Report

This module is organized in three high-level packages:

1. `attestdoc` where the data structures are defined
1. `attester` where a function to help generate an AWS Nitro Attestation Report in a Go application is defined; can only be used from within an Anjuna Nitro Enclave
1. `verifier` where Go functions are defined to help with unmarshalling and validating an AWS Nitro Attestation Report; can be used by applications running inside or outside an Anjuna Nitro Enclave

## Install

To install this module in your Go application, run:

```bash
go get github.com/anjuna-security/go-nitro-attestation
```

## How to use

Find below a high-level overview of how to use this module.

### Generate an AWS Nitro Attestation Report

If your application is running inside an Anjuna Nitro Enclave, be mindful that an endpoint is available internally to the Enclave. This endpoint can be used by your application to fetch a new Signed AWS Nitro Attestation Report. 

The endpoint is available at `http://localhost:50123` and the API is available in path `/api/v1/attestation/report`. The API accepts a `GET` request with a query parameter `userData` that can be used to provide custom data to the report. The custom data is optional and cannot exceed `1024 bytes`. The API will return the AWS Nitro Attestation Report as a CBOR-encoded COSE-signed binary document.

If your application was written in Go, you can use the package `attester` to easily communicate with the endpoint and generate a new Signed AWS Nitro Attestation Report.

Go Example:

```go
package main

import (
    "fmt"
    "github.com/anjuna-security/go-nitro-attestation/attester"
)

func main() {
    // defines your custom data
    myData := []byte("Hello World!")
    
    // get a new report byte stream
    docReader, err := attester.GetAttestationReport(myData) 
    if err != nil {
        panic(err)
    }

    docBytes, _ := io.ReadAll(docReader) // read the report's bytes
    fmt.Printf("%x", docBytes) // print the report's bytes
}
```

The function `GetAttestationReport` will return an `io.ReadCloser` object, result of a `GET` request to the endpoint. The `io.ReadCloser` object can be used to read the bytes of the report with `io.ReadAll`. 

If needed, you can unmarshal the report with `verifier.NewSignedAttestationReport`. The custom data you provided when calling the function will be available in the report's `Document.UserData` field and will be part of the report's final signature.

If your custom data exceeds `1024 bytes` we suggest you to send a hash of the data instead. This way you can still trust that the data was not tampered with and that it comes from a trusted source.

A common use case is for your application running inside an Anjuna Nitro Enclave to generate a new report and send it to an external application for validation upon request. For that reason, the `GetAttestationReport` function returns an `io.ReadCloser` object that can be used to optimize the transfer of the report's bytes between the two applications.

If your application is not written in Go and you still need access to the report, you can accomplish the same with any HTTP client. The endpoint will return a stream of bytes that can later be parsed and unmarshalled into an AWS Nitro Attestation Report.

Example without Go:

```bash
userData=$(echo "Hello World!" | base64)
curl http://localhost:50123/api/v1/attestation/report?userData="${userData}" > resonse.json
```

### Validate an AWS Nitro Attestation Report

After generating an AWS Nitro Attestation Report, you can validate it with the `verifier` package. The validation process consists of the following stages:

1. Validate the report's signature with regards to the report's root of trust. This is to ensure the report was generated by a true AWS Nitro Enclave.
1. Validate the report's PCR values. The PCR values that you trust are provided to you when you build any enclave image file with Anjuna.

To better illustrate how to validate a AWS Nitro Attestation Report, we will assume the report's bytes you want to validate are available in a file called `report.bin` and assume that you want the report's PCR0 value to be `000000` and the report's PCR1 value to be `000001`.

To validate the report with the help of the `verifier` package in your Go application, you can do something similar to the following:

```go
package main

import (
    "bufio"
    "fmt"

    "github.com/anjuna-security/go-nitro-attestation/verifier"
)

func main() {    
    // Unmarshal the report into a SignedAttestationReport object
    file, _ := os.Open("report.bin")
    report, err := verifier.NewSignedAttestationReport(bufio.NewReader(file))
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
```

Alternatively, and specially if you have a simple set of PCR values to check against, you can validate the report in one step by defining the `expectedPCRs` map to the call to `verifier.Validate` as shown below:

```go
package main

import (
    "encoding/hex"
    ...
)

func main() {
    ...
    // Validate the report's root of trust and PCR values
    expectedValues := {
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
```

After validating the report, you can access the report's custom data with `report.Document.UserData`. This is the data you provided when generating the report.
