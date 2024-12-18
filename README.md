# Anjuna Nitro Attestation

This repo defines the needed data structures and packages to:

1. Programmatically generate an AWS Nitro Attestation Report from an Anjuna Nitro Enclave
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

Below you will find a high-level overview of how to use this module.

### Generate an AWS Nitro Attestation Report

When running your application inside an Anjuna Nitro Enclave, there will be an internal endpoint available to the Enclave.
This endpoint can be used by your application to fetch a new Signed AWS Nitro Attestation Report.

The endpoint is available at `http://localhost:50123` and the API is available at the path `/api/v1/attestation/report`.
The API accepts a `GET` request with three optional base64 URL encoded parameters, each supporting up to 1024 bytes (after decoding):

  * `publicKey` for supplying a public key which is included in the attestation document.
    When using this API for the purpose of accessing secrets in KMS, an ASN.1 DER encoded RSA 2048 bit public key is expected.
  * `userData` for providing custom data to the report.
  * `nonce` to add a nonce value to the report for hardening the request against replay attacks.
    The `userData` parameter can also be used for this purpose.
    In either case a source of random data should be used for each request for it to be effective.

 The API will return the AWS Nitro Attestation Report as a CBOR-encoded COSE-signed binary document.

If your application was written in Go, you can use the package `attester` to easily communicate with the endpoint and generate a new Signed AWS Nitro Attestation Report.

[Go Example](./examples/attestation/main.go):

```go
// defines your custom data
myData := []byte("Hello World!")

// generate RSA-2048 key (optional)
rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
    panic(err)
}

// generate a 12 byte random nonce value
nonce := make([]byte, 12)
if _, err = rand.Read(nonce); err != nil {
    panic(err)
}

// get a new report byte stream (pass nil to rsaKey parameter if not used)
docReader, err := attester.GetAttestationReport(&rsaKey.PublicKey, myData, nonce)
if err != nil {
    panic(err)
}

docBytes, _ := io.ReadAll(docReader) // read the report's bytes
fmt.Printf("%x", docBytes)           // print the report's bytes
```

The function `GetAttestationReport` will return an `io.ReadCloser` object, the result of the `GET` request to the endpoint. The `io.ReadCloser` object can be used to read the bytes of the report with `io.ReadAll`. 

If needed, you can unmarshal the report with `verifier.NewSignedAttestationReport`. The custom data you provided when calling the function will be available in the report's `Document.UserData` field and will be part of the report's final signature. Additionally the `publicKey` and `nonce` can be accessed via the `Document.UserPublicKey` and `Document.UserNonce` fields respectively.

If your custom data exceeds `1024 bytes` we suggest you to send a hash of the data instead. This way you can still trust that the data was not tampered with and that it comes from a trusted source.

A common use case is when your application, running inside an Anjuna Nitro Enclave, generates a new report and sends it to an external application for validation upon request. For that reason, the `GetAttestationReport` function returns an `io.ReadCloser` object that can be used to optimize the transfer of the report's bytes between the two applications.

All parameters are optional. Section [2.2.2 of AWS's Nitro Attestation Process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#22-attestation-document-specification) specifies what each parameter can be used for. 

If your application is not written in Go and you still need access to the report, you can accomplish the same with any HTTP client. The endpoint will return a stream of bytes that can later be parsed and unmarshalled into an AWS Nitro Attestation Report.

Example in bash:

```bash
# Generate an RSA 2048 bit key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -outform DER -out public.der

userData=$(echo "Hello World!" | basenc -w0 --base64url)
publicKey=$(basenc -w0 --base64url public.der)
nonce=$(head -c 12 /dev/random | basenc -w0 --base64url)
curl "http://localhost:50123/api/v1/attestation/report?userData=${userData}&publicKey=${publicKey}&nonce=${nonce}" > report.bin
cat report.bin | basenc --base64 # to print the report's bytes in base64
```

**Note**: All of the query parameters are optional and can be used individually depending on your use case.

### Validate an AWS Nitro Attestation Report

After generating an AWS Nitro Attestation Report, you can validate it with the `verifier` package. The validation process consists of the following stages:

1. Validate the report's signature with regards to the report's root of trust. This is to ensure the report was generated by a true AWS Nitro Enclave.
1. Validate the report's PCR values. The PCR values of your application are provided to you when you [build any enclave image file with Anjuna](https://docs.anjuna.io/nitro/latest/getting_started/first_steps/first_steps_AWSNitro.html#_build_an_enclave_image_file_eif). Only you can tell what PCR values you trust.

To better illustrate how to validate an AWS Nitro Attestation Report, we will assume the report's bytes you want to validate are available in a file called `report.bin` and assume that you want the report's PCR0 value to be `000000` and the report's PCR1 value to be `000001`.

To validate the report with the help of the `verifier` package in your Go application, you can do something similar to the [following](./examples/validate_hexstr/main.go):

```go
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
```

Alternatively, and specially if you have a simple set of PCR values to check against, you can validate the report in one step by defining the `expectedPCRs` map to the call to `verifier.Validate` as [shown below](./examples/validate_pcrmap/main.go):

```go
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
```

After validating the report, you can access the report's custom data with `report.Document.UserData` as shown above.
This is the data you provided when generating the report.

The map of `expectedValues` you provide to the `verifier.Validate` function will be checked against the report's PCR values.
If any of the PCR values you provide do not match the report's PCR values, the validation will fail.
If the map of PCR values is not provided, the validation will not check the report's PCR values. It will still check the root of trust in all scenarios.

### Attestation and Decryption with KMS

The `UserPublicKey` field of an attestation document allows one to decrypt data securely with AWS KMS from inside an Anjuna Nitro Enclave.

By leveraging AWS's own [Go SDK](https://aws.github.io/aws-sdk-go-v2/docs/), one can communicate with KMS and decrypt data based on an attestation document generated with the Anjuna Nitro Attestation service.

You can find a complete step-by-step example of how to directly integrate with KMS for decryption using an Attestation Report in Anjuna's documentation website [here](https://docs.anjuna.io/nitro/latest/getting_started/how_to/attestation_endpoint_with_kms.html). 

## Examples

All the examples above can be found in the [`examples`](./examples/) folder. They have been written to be used as executables and not as libraries. They are not complete solutions by themselves and modifications are expected in order to better suit your use case and development practices.

Across all the examples, binary data input is assumed to be available as files in your file system. Textual inputs are expected as environment variables. No special error treatment is provided.
