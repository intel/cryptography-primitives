# Intel® Integrated Performance Primitives Cryptography

[Build Instructions](./BUILD.md) | [Contributing Guide](#how-to-contribute) | [Documentation](#documentation) | [Get Help](#get-help) | [Intel IPP Product Page](https://www.intel.com/content/www/us/en/developer/tools/oneapi/ipp.html)

Intel® Integrated Performance Primitives Cryptography (Intel® IPP Cryptography) is a secure, fast and lightweight library of building blocks for cryptography, highly-optimized for various Intel® CPUs.

## Key Features
The library provides a comprehensive set of routines commonly used for cryptographic operations, including:
 - Symmetric Cryptography Primitive Functions:
    - AES (ECB, CBC, CTR, OFB, CFB, XTS, GCM, CCM, SIV)
    - SM4 (ECB, CBC, CTR, OFB, CFB, CCM)
    - TDES (ECB, CBC, CTR, OFB, CFB)
    - RC4
- One-Way Hash Primitives:
    - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
    - MD5
    - SM3
- Data Authentication Primitive Functions:
   - HMAC
   - AES-CMAC
- Public Key Cryptography Functions:
   - RSA, RSA-OAEP, RSA-PKCS_v15, RSA-PSS
   - DLP, DLP-DSA, DLP-DH
   - ECC (NIST curves), ECDSA, ECDH, EC-SM2
- Multi-buffer RSA, ECDSA, ECDH, x25519, SM2, SM3, SM4, etc
- Finite Field Arithmetic Functions
- Big Number Integer Arithmetic Functions
- PRNG/TRNG and Prime Numbers Generation
- Hash-based signature algorithms

## Reasons to Use Intel IPP Cryptography
- Security (constant-time execution for secret processing functions)
- Designed for the small footprint size
- Optimized for different Intel CPUs and instruction set architectures (including hardware cryptography instructions support):
    - Intel® Streaming SIMD Extensions 2 (Intel® SSE2)
    - Intel® SSE3
    - Intel® SSE4.2
    - Intel® Advanced Vector Extensions (Intel® AVX)
    - Intel® Advanced Vector Extensions 2 (Intel® AVX2)
    - Intel® Advanced Vector Extensions 512 (Intel® AVX-512)
- Configurable CPU dispatching for the best performance
- Kernel mode compatibility
- Thread-safe design

## FIPS 140 Compliance

Intel IPP Cryptography supports building blocks (self-tests, services) for FIPS 140-3 compliance.
See [FIPS] (./README_FIPS.md) document for details.

## Installation

[How to Get and Build the Intel IPP Cryptography Library](./BUILD.md)

## Documentation

- [Introduction to Intel IPP Cryptography Library](./OVERVIEW.md)
- [Introduction to Crypto Multi-buffer Library](./sources/ippcp/crypto_mb/Readme.md)
- [Intel IPP Cryptography Build Instructions](./BUILD.md)
- [Intel IPP Release Notes](https://www.intel.com/content/www/us/en/developer/articles/release-notes/release-notes-for-oneapi-integrated-performance-primitives.html)
- [Intel IPP Cryptography Developer Reference](https://www.intel.com/content/www/us/en/docs/ipp-crypto/developer-reference/current/overview.html)
- [Intel IPP Documentation](https://www.intel.com/content/www/us/en/developer/tools/oneapi/ipp-documentation.html)

## Branches Description

- `develop` - snapshots of the library under active development.
Contains code that may not be fully functional and that Intel may substantially modify in development of a production version.
- `ipp_crypto_<release>` - source code of the official production release `<release>`.

## How to Contribute

See [Contributing](./CONTRIBUTING.md) document for details about contribution process.

### License
Intel IPP Cryptography is licensed under Apache License, Version 2.0. By contributing to the project, you agree to the license and copyright terms therein and release your contribution under these terms.

## Certification

Intel IPP Cryptography 2021.10 release is validated for FIPS-140-3 (Security Requirements for Cryptographic Modules) compliance and has the following CAVP (Cryptographic Algorithm Validation Program) certificates:

- [Intel® Crypto Multi-buffer Library](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=17987)
- [Intel® Integrated Performance Primitives Cryptography (Intel® IPP Cryptography) optimized for Intel® AVX2 ISA](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=17988)
- [Intel® Integrated Performance Primitives Cryptography (Intel® IPP Cryptography) optimized for Intel® AVX512 ISA](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=17989)
