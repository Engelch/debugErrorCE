package debugerrorce

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"crypto/sha256"
	"crypto/x509"

	"github.com/stretchr/testify/assert"
)

func TestPemToPubKey(t *testing.T) {
	const publicKey = `
		MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9sc3FCBC3x9kTPpKTzl/
		qQct3NcjfrTsrqNloaTCncXtSAln2X+yClCmaVIrpQOyL7TbCXniKojmJhMOdhfH
		V6sWmFiFQV3XJyzQFXbCX3dE/v5uy21l4xrZtkLcX4JzsS6fpsf2avO48OM6ZCNO
		MHO5ifXUoHYVG5ApP4P5B4j0AVg7rSb4HWIX2cv+K6+p47dYgV5N2XO0z6g+ZsK6
		yAuklaHU5b1yhrYjpRdXgCeukwaNHI8YqiDpSWrSxE5pmBsL2EP3z5jLydgwacPJ
		x1MEI+4a4ta0ivsr1sgrd5UwvmrnVRhn/3Vl8Q5AKie3zpOhtiH3mhZOwhxndlsG
		5T0v6RY1/ZEdMYSl/DSaYYZQgEqsiJJQLpsgfNZZJI4fPfHiaRvhDVB8O78CwNzj
		20mHCymY9pgFStdsdneFsZr6dFwyCtDCI9uXv1jNnr+x3GSqlR4fIsZOzNGOkR15
		yXjbSYwCeegJJsvUp15jGaKt6QVKQSaXjfKVG2wOzIiNJCrjrme1k4p2Fte+/Qkl
		xPmL0nPjvIuyLZmeNRVNy8SroSvC5YoGyvWWQkl5QOQtRM/nA84jriVw0q2/YacN
		QQ5cLFehoFQqJB2wn+x7wSrSDgeOHC2S2QQXd1GTkRMPNfgMBIQrgprGmcnkD5Uv
		RaYRL1gjPNuOwGW0lLt/lDsCAwEAAQ==
	`
	str := "-----BEGIN PUBLIC KEY-----" + // line feeds not required
		strings.Replace(strings.Replace(publicKey, " ", "", -1), "\t", "", -1) + // remove spaces + tabs
		"-----END PUBLIC KEY-----"
	block, _ := pem.Decode([]byte(str))
	assert.NotNil(t, block, "pem.Decode error")

	// fmt.Print(strings.Replace(strings.Replace(publicKey, " ", "", -1), "\t", "", -1))
	_, err := Pem2RsaPublicKey([]byte(str))

	assert.Nil(t, err, "could not decipher public key")
}

func TestACorrectCSR(t *testing.T) {
	const pemCsr = `
-----BEGIN CERTIFICATE REQUEST-----
MIIEbTCCAlUCAQAwKDELMAkGA1UEBhMCWloxGTAXBgNVBAMMEG9wZW5zc2xyZXFf
dW5lbmMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQD2xzcUIELfH2RM
+kpPOX+pBy3c1yN+tOyuo2WhpMKdxe1ICWfZf7IKUKZpUiulA7IvtNsJeeIqiOYm
Ew52F8dXqxaYWIVBXdcnLNAVdsJfd0T+/m7LbWXjGtm2QtxfgnOxLp+mx/Zq87jw
4zpkI04wc7mJ9dSgdhUbkCk/g/kHiPQBWDutJvgdYhfZy/4rr6njt1iBXk3Zc7TP
qD5mwrrIC6SVodTlvXKGtiOlF1eAJ66TBo0cjxiqIOlJatLETmmYGwvYQ/fPmMvJ
2DBpw8nHUwQj7hri1rSK+yvWyCt3lTC+audVGGf/dWXxDkAqJ7fOk6G2IfeaFk7C
HGd2WwblPS/pFjX9kR0xhKX8NJphhlCASqyIklAumyB81lkkjh898eJpG+ENUHw7
vwLA3OPbSYcLKZj2mAVK12x2d4Wxmvp0XDIK0MIj25e/WM2ev7HcZKqVHh8ixk7M
0Y6RHXnJeNtJjAJ56Akmy9SnXmMZoq3pBUpBJpeN8pUbbA7MiI0kKuOuZ7WTinYW
1779CSXE+YvSc+O8i7ItmZ41FU3LxKuhK8LligbK9ZZCSXlA5C1Ez+cDziOuJXDS
rb9hpw1BDlwsV6GgVCokHbCf7HvBKtIOB44cLZLZBBd3UZOREw81+AwEhCuCmsaZ
yeQPlS9FphEvWCM8247AZbSUu3+UOwIDAQABoAAwDQYJKoZIhvcNAQELBQADggIB
ADD0YH1pW2lOyqoT3n3cGeM4iPt6MMtHek4T6+lVImEXzfoioU5GEv+pfZBdG9wA
waQAZ+cb/x7BNStM6ZpdvZYZKX81jHcrx85sprk5oMgcrCTkawVZnvG5SC01FsUD
0BmowXRpEM/5h/wFdpDRfg3lvR65pNtCZadXydCtumQISo7IKbLHxWNF/be07zVy
QCL2c6wR1LHJyfH9GOeCLUyCHifjuOzNdVTvpuqnnHBSK1v86XW/zBHxiPsKPsP1
gLt8u5Da7/gtFZkYHAPDKbkY9wljDMIY7k7BOy0r7wxq2Bx1vyIGdt4RDlDLg3yC
zJp4eiWmLRAJ9xUFR1Zm9uXhJ2MSaSPsOH6ctoK47KP09um8hUUKwXFvmsnoH0St
WsJJtHkvKMxfJe7qQKO6efWqkEZcLQJf0NWeNbFWpMBx5P+b89eKXvl2U3ESp1am
vSXfHySld88mTB3jEucwBtm7NelhVhj3kwxB0VFrsGUnnW6gOFQlM+U/MJH23mjE
oqjJjUQ8ErPfVWZXsV7aBAakFgcyPSefCafENlKfDRI4KVQxWtWXOZeGp0/pzpEw
SrwZoQ0iFZlO0osLRb+A3S6Jwf4Ls55eZU9HgicgWNs3xhyuEgUoJ8QrIyFst1HH
pQ3dQDkR/QCqbIaO7P/1J8YDCkBqCUUV7xWp74dmSzbP
-----END CERTIFICATE REQUEST-----
	`
	csr, err := Pem2CSR([]byte(pemCsr))
	assert.Nil(t, err, "error in Pem2CSR")
	_, err = Any2RsaPublicKey(csr.PublicKey)
	assert.Nil(t, err, "error in Any2RsaPublicKey")
}

func TestUnformattedFailingCSR(t *testing.T) {
	const pemCsr = `
		-----BEGIN CERTIFICATE REQUEST-----
		MIIEbTCCAlUCAQAwKDELMAkGA1UEBhMCWloxGTAXBgNVBAMMEG9wZW5zc2xyZXFf
		dW5lbmMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQD2xzcUIELfH2RM
		+kpPOX+pBy3c1yN+tOyuo2WhpMKdxe1ICWfZf7IKUKZpUiulA7IvtNsJeeIqiOYm
		Ew52F8dXqxaYWIVBXdcnLNAVdsJfd0T+/m7LbWXjGtm2QtxfgnOxLp+mx/Zq87jw
		4zpkI04wc7mJ9dSgdhUbkCk/g/kHiPQBWDutJvgdYhfZy/4rr6njt1iBXk3Zc7TP
		qD5mwrrIC6SVodTlvXKGtiOlF1eAJ66TBo0cjxiqIOlJatLETmmYGwvYQ/fPmMvJ
		2DBpw8nHUwQj7hri1rSK+yvWyCt3lTC+audVGGf/dWXxDkAqJ7fOk6G2IfeaFk7C
		HGd2WwblPS/pFjX9kR0xhKX8NJphhlCASqyIklAumyB81lkkjh898eJpG+ENUHw7
		vwLA3OPbSYcLKZj2mAVK12x2d4Wxmvp0XDIK0MIj25e/WM2ev7HcZKqVHh8ixk7M
		0Y6RHXnJeNtJjAJ56Akmy9SnXmMZoq3pBUpBJpeN8pUbbA7MiI0kKuOuZ7WTinYW
		1779CSXE+YvSc+O8i7ItmZ41FU3LxKuhK8LligbK9ZZCSXlA5C1Ez+cDziOuJXDS
		rb9hpw1BDlwsV6GgVCokHbCf7HvBKtIOB44cLZLZBBd3UZOREw81+AwEhCuCmsaZ
		yeQPlS9FphEvWCM8247AZbSUu3+UOwIDAQABoAAwDQYJKoZIhvcNAQELBQADggIB
		ADD0YH1pW2lOyqoT3n3cGeM4iPt6MMtHek4T6+lVImEXzfoioU5GEv+pfZBdG9wA
		waQAZ+cb/x7BNStM6ZpdvZYZKX81jHcrx85sprk5oMgcrCTkawVZnvG5SC01FsUD
		0BmowXRpEM/5h/wFdpDRfg3lvR65pNtCZadXydCtumQISo7IKbLHxWNF/be07zVy
		QCL2c6wR1LHJyfH9GOeCLUyCHifjuOzNdVTvpuqnnHBSK1v86XW/zBHxiPsKPsP1
		gLt8u5Da7/gtFZkYHAPDKbkY9wljDMIY7k7BOy0r7wxq2Bx1vyIGdt4RDlDLg3yC
		zJp4eiWmLRAJ9xUFR1Zm9uXhJ2MSaSPsOH6ctoK47KP09um8hUUKwXFvmsnoH0St
		WsJJtHkvKMxfJe7qQKO6efWqkEZcLQJf0NWeNbFWpMBx5P+b89eKXvl2U3ESp1am
		vSXfHySld88mTB3jEucwBtm7NelhVhj3kwxB0VFrsGUnnW6gOFQlM+U/MJH23mjE
		oqjJjUQ8ErPfVWZXsV7aBAakFgcyPSefCafENlKfDRI4KVQxWtWXOZeGp0/pzpEw
		SrwZoQ0iFZlO0osLRb+A3S6Jwf4Ls55eZU9HgicgWNs3xhyuEgUoJ8QrIyFst1HH
		pQ3dQDkR/QCqbIaO7P/1J8YDCkBqCUUV7xWp74dmSzbP
		-----END CERTIFICATE REQUEST-----
	`
	_, err := Pem2CSR([]byte(pemCsr))
	assert.NotNil(t, err, "got not expected error")
}

func TestCSR2Sha256OfPubKey(t *testing.T) {
	const pemCsr = `
-----BEGIN CERTIFICATE REQUEST-----
MIIEbTCCAlUCAQAwKDELMAkGA1UEBhMCWloxGTAXBgNVBAMMEG9wZW5zc2xyZXFf
dW5lbmMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQD2xzcUIELfH2RM
+kpPOX+pBy3c1yN+tOyuo2WhpMKdxe1ICWfZf7IKUKZpUiulA7IvtNsJeeIqiOYm
Ew52F8dXqxaYWIVBXdcnLNAVdsJfd0T+/m7LbWXjGtm2QtxfgnOxLp+mx/Zq87jw
4zpkI04wc7mJ9dSgdhUbkCk/g/kHiPQBWDutJvgdYhfZy/4rr6njt1iBXk3Zc7TP
qD5mwrrIC6SVodTlvXKGtiOlF1eAJ66TBo0cjxiqIOlJatLETmmYGwvYQ/fPmMvJ
2DBpw8nHUwQj7hri1rSK+yvWyCt3lTC+audVGGf/dWXxDkAqJ7fOk6G2IfeaFk7C
HGd2WwblPS/pFjX9kR0xhKX8NJphhlCASqyIklAumyB81lkkjh898eJpG+ENUHw7
vwLA3OPbSYcLKZj2mAVK12x2d4Wxmvp0XDIK0MIj25e/WM2ev7HcZKqVHh8ixk7M
0Y6RHXnJeNtJjAJ56Akmy9SnXmMZoq3pBUpBJpeN8pUbbA7MiI0kKuOuZ7WTinYW
1779CSXE+YvSc+O8i7ItmZ41FU3LxKuhK8LligbK9ZZCSXlA5C1Ez+cDziOuJXDS
rb9hpw1BDlwsV6GgVCokHbCf7HvBKtIOB44cLZLZBBd3UZOREw81+AwEhCuCmsaZ
yeQPlS9FphEvWCM8247AZbSUu3+UOwIDAQABoAAwDQYJKoZIhvcNAQELBQADggIB
ADD0YH1pW2lOyqoT3n3cGeM4iPt6MMtHek4T6+lVImEXzfoioU5GEv+pfZBdG9wA
waQAZ+cb/x7BNStM6ZpdvZYZKX81jHcrx85sprk5oMgcrCTkawVZnvG5SC01FsUD
0BmowXRpEM/5h/wFdpDRfg3lvR65pNtCZadXydCtumQISo7IKbLHxWNF/be07zVy
QCL2c6wR1LHJyfH9GOeCLUyCHifjuOzNdVTvpuqnnHBSK1v86XW/zBHxiPsKPsP1
gLt8u5Da7/gtFZkYHAPDKbkY9wljDMIY7k7BOy0r7wxq2Bx1vyIGdt4RDlDLg3yC
zJp4eiWmLRAJ9xUFR1Zm9uXhJ2MSaSPsOH6ctoK47KP09um8hUUKwXFvmsnoH0St
WsJJtHkvKMxfJe7qQKO6efWqkEZcLQJf0NWeNbFWpMBx5P+b89eKXvl2U3ESp1am
vSXfHySld88mTB3jEucwBtm7NelhVhj3kwxB0VFrsGUnnW6gOFQlM+U/MJH23mjE
oqjJjUQ8ErPfVWZXsV7aBAakFgcyPSefCafENlKfDRI4KVQxWtWXOZeGp0/pzpEw
SrwZoQ0iFZlO0osLRb+A3S6Jwf4Ls55eZU9HgicgWNs3xhyuEgUoJ8QrIyFst1HH
pQ3dQDkR/QCqbIaO7P/1J8YDCkBqCUUV7xWp74dmSzbP
-----END CERTIFICATE REQUEST-----
	`
	csr, err := Pem2CSR([]byte(pemCsr))
	assert.Nil(t, err, "error in Pem2CSR")
	pubkey, err := Any2RsaPublicKey(csr.PublicKey)
	assert.Nil(t, err, "error in Any2RsaPublicKey")
	fmt.Println("Sha256 pubkey:" + fmt.Sprintf("%x", Bytes2sha256([]byte(fmt.Sprintf("%v", pubkey)))))
	keyDER, err := x509.MarshalPKIXPublicKey(pubkey)
	assert.NotNil(t, err, "keyDer marshall")

	fmt.Println("Sha256(DER Version):", fmt.Sprintf("%x", Bytes2sha256(keyDER)))
}

// MustMarshalPublicPEMToDER reads a PEM-encoded public key and returns it in DER encoding.
// If an error occurs, it panics.
func mustMarshalPublicPEMToDER(keyPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New(CurrentFunctionName() + ":ERROR decoding PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New(CurrentFunctionName() + ":ERROR parsinPkiXPublicKey")
	}

	keyDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, errors.New(CurrentFunctionName() + ":ERROR MarshalPKIXPublicKey")

	}
	return keyDER, nil
}

func Bytes2sha256base64(bytes []byte) string {
	//return fmt.Sprintf("%x", sha256.Sum256(bytes)) returning type array [32]byte which must usually be converted
	msgHash := sha256.New()
	_, _ = msgHash.Write(bytes) // todo no error handling, but error is very unlike
	return fmt.Sprintf("%x", msgHash.Sum(nil))
}

func TestPubKey2Sha256(t *testing.T) {
	const publicKey = `
		MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9sc3FCBC3x9kTPpKTzl/
		qQct3NcjfrTsrqNloaTCncXtSAln2X+yClCmaVIrpQOyL7TbCXniKojmJhMOdhfH
		V6sWmFiFQV3XJyzQFXbCX3dE/v5uy21l4xrZtkLcX4JzsS6fpsf2avO48OM6ZCNO
		MHO5ifXUoHYVG5ApP4P5B4j0AVg7rSb4HWIX2cv+K6+p47dYgV5N2XO0z6g+ZsK6
		yAuklaHU5b1yhrYjpRdXgCeukwaNHI8YqiDpSWrSxE5pmBsL2EP3z5jLydgwacPJ
		x1MEI+4a4ta0ivsr1sgrd5UwvmrnVRhn/3Vl8Q5AKie3zpOhtiH3mhZOwhxndlsG
		5T0v6RY1/ZEdMYSl/DSaYYZQgEqsiJJQLpsgfNZZJI4fPfHiaRvhDVB8O78CwNzj
		20mHCymY9pgFStdsdneFsZr6dFwyCtDCI9uXv1jNnr+x3GSqlR4fIsZOzNGOkR15
		yXjbSYwCeegJJsvUp15jGaKt6QVKQSaXjfKVG2wOzIiNJCrjrme1k4p2Fte+/Qkl
		xPmL0nPjvIuyLZmeNRVNy8SroSvC5YoGyvWWQkl5QOQtRM/nA84jriVw0q2/YacN
		QQ5cLFehoFQqJB2wn+x7wSrSDgeOHC2S2QQXd1GTkRMPNfgMBIQrgprGmcnkD5Uv
		RaYRL1gjPNuOwGW0lLt/lDsCAwEAAQ==
	`

	str := "-----BEGIN PUBLIC KEY-----" + // line feeds not required
		strings.Replace(strings.Replace(publicKey, " ", "", -1), "\t", "", -1) + // remove spaces + tabs
		"-----END PUBLIC KEY-----"

	der, err := mustMarshalPublicPEMToDER(str)
	assert.Nil(t, err, "marshalling")

	fmt.Printf("(DER): %x\n", der)
	fmt.Printf("b64(DER): %s\n", base64.StdEncoding.EncodeToString(der))
	fmt.Println("sha256(DER):", base64.StdEncoding.EncodeToString(Bytes2sha256(der)))
	fmt.Println("sha256(DER) 2:", fmt.Sprintf("%x", Bytes2sha256(der)))
	fmt.Println("demo:", base64.StdEncoding.EncodeToString([]byte("demo\n")))
	fmt.Println("demo: sha256", Bytes2sha256base64([]byte("demo\n")))
}

func TestPubKeyFields(t *testing.T) {
    const publicKey = `
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9sc3FCBC3x9kTPpKTzl/
qQct3NcjfrTsrqNloaTCncXtSAln2X+yClCmaVIrpQOyL7TbCXniKojmJhMOdhfH
V6sWmFiFQV3XJyzQFXbCX3dE/v5uy21l4xrZtkLcX4JzsS6fpsf2avO48OM6ZCNO
MHO5ifXUoHYVG5ApP4P5B4j0AVg7rSb4HWIX2cv+K6+p47dYgV5N2XO0z6g+ZsK6
yAuklaHU5b1yhrYjpRdXgCeukwaNHI8YqiDpSWrSxE5pmBsL2EP3z5jLydgwacPJ
x1MEI+4a4ta0ivsr1sgrd5UwvmrnVRhn/3Vl8Q5AKie3zpOhtiH3mhZOwhxndlsG
5T0v6RY1/ZEdMYSl/DSaYYZQgEqsiJJQLpsgfNZZJI4fPfHiaRvhDVB8O78CwNzj
20mHCymY9pgFStdsdneFsZr6dFwyCtDCI9uXv1jNnr+x3GSqlR4fIsZOzNGOkR15
yXjbSYwCeegJJsvUp15jGaKt6QVKQSaXjfKVG2wOzIiNJCrjrme1k4p2Fte+/Qkl
xPmL0nPjvIuyLZmeNRVNy8SroSvC5YoGyvWWQkl5QOQtRM/nA84jriVw0q2/YacN
QQ5cLFehoFQqJB2wn+x7wSrSDgeOHC2S2QQXd1GTkRMPNfgMBIQrgprGmcnkD5Uv
RaYRL1gjPNuOwGW0lLt/lDsCAwEAAQ==
`

    str := "-----BEGIN PUBLIC KEY-----" + // line feeds not required
    strings.Replace(strings.Replace(publicKey, " ", "", -1), "\t", "", -1) + // remove spaces + tabs
    "-----END PUBLIC KEY-----"
    block, _ := pem.Decode([]byte(str))
    assert.NotNil(t, block, "pem.Decode error")

    // fmt.Print(strings.Replace(strings.Replace(publicKey, " ", "", -1), "\t", "", -1))
    key, err := Pem2RsaPublicKey([]byte(str))
    assert.Nil(t, err, "convert to RSA pub key")

    fmt.Println("key", key)
    DebugRsaPublicKey(key)
    fmt.Printf("Modulus %d\n", key.N)
    fmt.Printf("Modulus in Hex %X\n", key.N)
    fmt.Printf("Expoent in  Hex is %X", key.E)
    fmt.Printf("Sha256 of modulus is %X\n", string(Bytes2sha256([]byte(fmt.Sprintf("%X", key.N)))))
    fmt.Println("debug exponent, modulus", fmt.Sprintf("%X,%X", key.E, key.N))
    fmt.Printf("Sha256 of exponent,modulus is %x\n", string(Bytes2sha256([]byte(fmt.Sprintf("%X,%X", key.E, key.N)))))
}

// EOF
