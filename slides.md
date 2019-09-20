---
title: Certificates
theme: moon
revealOptions:
    transition: 'none'
css: slides.css
---

## Certificates

---

## What are they?

### In the real world

- A statement that a key pair is owned by a particular entity (person, web site, ...)
- Digital equivalent of witnessing someone's signature
- Signed by an "authority"

---

## What are they?

### In terms of crypto / technology

- Encoded
- Digitally signed
- Payload contains public key plus identifying metadata

---

## Encoding

From the outside in:

- PEM (optional)
- DER
- ASN.1

---

## PEM encoding

PEM = privacy enchanced mail

Just header and footer lines enclosing Base64 encoding of the binary DER encoding

```

-----BEGIN CERTIFICATE-----
MIICWjCCAcMCAgGlMA0GCSqGSIb3DQEBBAUAMHUxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9HVEUg
Q29ycG9yYXRpb24xJzAlBgNVBAsTHkdURSBDeWJlclRydXN0IFNvbHV0aW9ucywgSW5jLjEjMCEG
A1UEAxMaR1RFIEN5YmVyVHJ1c3QgR2xvYmFsIFJvb3QwHhcNOTgwODEzMDAyOTAwWhcNMTgwODEz
MjM1OTAwWjB1MQswCQYDVQQGEwJVUzEYMBYGA1UEChMPR1RFIENvcnBvcmF0aW9uMScwJQYDVQQL
Ex5HVEUgQ3liZXJUcnVzdCBTb2x1dGlvbnMsIEluYy4xIzAhBgNVBAMTGkdURSBDeWJlclRydXN0
IEdsb2JhbCBSb290MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVD6C28FCc6HrHiM3dFw4u
sJTQGz0O9pTAipTHBsiQl8i4ZBp6fmw8U+E3KHNgf7KXUwefU/ltWJTSr41tiGeA5u2ylc9yMcql
HHK6XALnZELn+aks1joNrI1CqiQBOeacPwGFVw1Yh0X404Wqk2kmhXBIgD8SFcd5tB8FLztimQID
AQABMA0GCSqGSIb3DQEBBAUAA4GBAG3rGwnpXtlR22ciYaQqPEh346B8pt5zohQDhT37qw4wxYMW
M4ETCJ57NE7fQMh017l93PR2VX2bY1QY6fDq81yx2YtCHrnAlU66+tXifPVoYb+O7AWXX1uw16OF
NMQkpw0PlZPvy5TYnh+dXIVtx6quTx8itc2VrbqnzPmrC3p/
-----END CERTIFICATE-----
```

---

## DER encoding

- "Distinguished encoding rules"
- Not very interesting for us
- Just a standard binary encoding for ASN.1
- There's also the Basic Encoding Rules = BER

---

## ASN.1

- "Abstract Syntax Notation #1"
- A formalised / standard way of defining data structures
- The ASN.1 definition for X.509 certificates is in RFC5280

```
   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }
```

- TBS stands for "To Be Signed"

---

## TBSCertificate structure

```
   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }
```

- Almost all certificates seen now are version 3

---

## Distinguished names

- The `issuer` and `subject` fields contain "Distinguished Names"
- These are sequences of key-value pairs with fields like
  - country,
  - organization,
  - organizational unit,
  - state or province name,
  - common name
  - locality

`C=US, O=GTE Corporation, OU="GTE CyberTrust Solutions, Inc.", CN=GTE CyberTrust
Global Root`

---

## Process

1. Generate a key pair
2. Create a Certificate Signing Request (CSR)
   - This contains the public key
   - The distinguished name of the owner
   - Encoded and signed by the private key
3. Certificate Authority (CA) creates the certificate
   - Verifies identity of applicant*
   - Adds metadata (validity, extensions covering use)
   - DER encodes the resulting TBSCertificate
   - Signs that with *their* private key

---

## Trust

- So you can trust a certificate if you trust its signer
  - And if the crypto used is good (key length, signature algorithm)
- But why should you?
- Why would you trust a witnessed signature?
  - If you know the person and recognise their signature...?
- The signer also has a certificate, containing their public key
- You can verify that this matches the signature of your certificate
- But that just pushes the problem up one level: Who signed their certificate,
  and can you trust them?

---

## CA certificates

- Among the X.509 v3 extension metadata is a boolean field that says
  whether this key pair is authorised for signing certificates.
- A certificate with `CA: True` is a "CA certificate"

---

## Certificate chains

- A certificate can be bundled together with the certificate of its issuer, and
  so on.
- PEM ASCII certificate files can just be concatenated
- All but the bottom end of the chain (the "end-user" certificate) must be CA
  certificates
- At the top end of the chain is a self-signed CA certificate or "root CA
  certificate"
- So the question of trust reduces to: Do you trust the root CA at the top of
  the chain?
- In practice this usually means: Does my browser contain a copy of that root CA
  cert?

---

## Example

- If I download the certificate chain for <https://analyzer.cryptosense.com>, the
  resulting file has three certificates in it

```bash
$ cat analyzer.crt.pem
-----BEGIN CERTIFICATE-----
MIIFaTCCBFGgAwIBAgISA0EVunEjlEAl0tIuu5r3z0aiMA0GCSqGSIb3DQEBCwUA

... Several lines omitted ...

0MQf6pRTYPFrTXxHe83AJjZjzVpLCSU03nlSoaO0J95FCEaE8aoLMo7Psvpd
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw

... Several lines omitted ...

rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw

... Several lines omitted ...

emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
```

---

## The end-user cert

The first part contains the Cryptosense end-user certificate, signed by Let's
Encrypt Authority X3

```bash
$ openssl x509 -noout -inform pem -text -in analyzer-1.crt.pem 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            03:41:15:ba:71:23:94:40:25:d2:d2:2e:bb:9a:f7:cf:46:a2
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
        Validity
            Not Before: Aug  1 23:32:34 2019 GMT
            Not After : Oct 30 23:32:34 2019 GMT
        Subject: CN = analyzer.cryptosense.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:d0:9a:9d:ca:0d:2a:ee:ac:ab:47:9a:88:de:55:

                    ... Several lines omitted ...

                    a9:f4:f3:b7:6d:81:8f:2c:92:eb:08:d4:af:ae:41:
                    e5:a7
                Exponent: 65537 (0x10001)
```

---

## End-user certificate continued...

```bash
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                A8:B0:F2:8A:31:50:B9:22:5C:D7:52:27:24:4C:FE:BC:04:84:1D:64
            X509v3 Authority Key Identifier: 
                keyid:A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1

            ... Several lines omitted ...

            X509v3 Subject Alternative Name: 
                DNS:analyzer.cryptosense.com

            ... Several lines omitted ...

    Signature Algorithm: sha256WithRSAEncryption
         9a:57:97:10:ca:72:01:ab:29:19:a5:0d:5d:90:48:be:a2:7a:

         ... Several lines omitted ...

         34:de:79:52:a1:a3:b4:27:de:45:08:46:84:f1:aa:0b:32:8e:
         cf:b2:fa:5d
```

---

## Issuer certificate

```bash
$ openssl x509 -noout -inform pem -text -in analyzer-2.crt.pem

... Several lines omitted ...

        Issuer: C = US, O = Internet Security Research Group, CN = ISRG Root X1
        Validity
            Not Before: Oct  6 15:43:55 2016 GMT
            Not After : Oct  6 15:43:55 2021 GMT
        Subject: C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3

... Several lines omitted ...

        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0

... Several lines omitted ...

            X509v3 Subject Key Identifier: 
                A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1

... Several lines omitted ...

            X509v3 Authority Key Identifier: 
                keyid:79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E
```

---

## Root certificate

```bash
$ openssl x509 -noout -inform pem -text -in analyzer-3.crt.pem 

... Several lines omitted ...
        Serial Number:
            82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Internet Security Research Group, CN = ISRG Root X1
        Validity
            Not Before: Jun  4 11:04:38 2015 GMT
            Not After : Jun  4 11:04:38 2035 GMT
        Subject: C = US, O = Internet Security Research Group, CN = ISRG Root X1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)

... Several lines omitted ...

        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E

... Several lines omitted ...
```

---

## Verifying the chain

- The `openssl verify` command can verify that chain
- We have to label the self-signed root certificate
- We explicitly say that we don't necessarily trust the intermediate certificate
  and the tool should verify that too

```bash
$ openssl verify --CAfile analyzer-3.crt.pem \
-untrusted analyzer-2.crt.pem analyzer-1.crt.pem 
analyzer-1.crt.pem: OK
```

- This checks the validity dates, certificate uses etc. and then verifies the
  signatures all the way up the chain

---

## Trust again

- When my browser connects to the analyzer web app, it gets a copy of the
  end-user certificate
- As part of the connection, the web site proves that it has a copy of the
  matching private key (by signing a nonce or similar)
- The browser can verify the integrity of the chain leading to it (by checking
  that each certificate signature matches the public key in the issuer
  certificate)
- Some browsers come with a bundle of trusted root CA certs. Chrome actually
  uses the OS's certificate list. In the case of Linux, this is provided by the
  Mozilla NSS library (!)

---

## Closing the loop

```bash
  $ ls /usr/share/ca-certificates/mozilla/ISRG*
/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt
$ openssl x509 -noout -text \
    -in /usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt

... Several lines omitted ...

        Serial Number:
            82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00

... Several lines omitted ...

            X509v3 Subject Key Identifier: 
                79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E
```

- It matches! So my browser trusts the analyzer.

---

## Notes

- Anybody can create a self-signed root CA certificate, but getting someone else
  to trust it is another matter
- There is nothing special technically about the root CA certs trusted by our
  browsers, in fact some of them have out of date / weak key lengths, signature
  algorithms, over-long validity
- But for internal use it is entirely possible to set up our own PKI: that's
  what we do for GitLab
- OpenSSL command-line tools `openssl x509`, `openssl asn1`, `openssl req` and
  related are very useful

---
