# Intel® Cryptography Primitives Library

[Build Instructions](./BUILD.md) | [Contributing Guide](#how-to-contribute) | [Documentation](#documentation) | [Get Help](./SUPPORT.md) | [Homepage](https://www.intel.com/content/www/us/en/developer/tools/oneapi/crypto-library/overview.html)

Intel® Cryptography Primitives Library is a secure, fast and lightweight library of building blocks for cryptography, highly-optimized for various Intel® CPUs.

## Key Features
The library provides a comprehensive set of routines commonly used for cryptographic operations, including:
 - Post-Quantum Cryptography Functions:
    - Digital signature algorithms
       - Stateful (XMSS, LMS).
       - Stateless (ML-DSA).
    - Key encapsulation mechanism (ML-KEM)
 - Symmetric Cryptography Primitive Functions:
    - AES (ECB, CBC, CTR, OFB, CFB, XTS, GCM, CCM, SIV)
    - SM4 (ECB, CBC, CTR, OFB, CFB, CCM)
    - TDES (ECB, CBC, CTR, OFB, CFB)
    - RC4
- One-Way Hash Primitives:
    - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
    - SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256
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

## Reasons to Use Intel® Cryptography Primitives Library
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

Intel® Cryptography Primitives Library supports building blocks (self-tests, services) for FIPS 140-3 compliance.
See [FIPS](./README_FIPS.md) document for details.

## Installation

[How to Get and Build the Intel® Cryptography Primitives Library](./BUILD.md)

## Documentation

- [Introduction to Intel® Cryptography Primitives Library](./OVERVIEW.md)
- [Introduction to Crypto Multi-buffer Library](./sources/ippcp/crypto_mb/Readme.md)
- [Intel® Cryptography Primitives Library Build Instructions](./BUILD.md)
- [Intel® Cryptography Primitives Library Release Notes](https://www.intel.com/content/www/us/en/developer/articles/release-notes/cryptography-primitives-library.html)
- [Developer Guide and Reference for Intel® Cryptography Primitives Library](https://www.intel.com/content/www/us/en/docs/crypto-primitives-library/developer-guide-reference/current/overview.html)

## Branches Description

- `develop` - snapshots of the library under active development.
Contains code that may not be fully functional and that Intel may substantially modify in development of a production version.
- `cryptography-primitives_<release>` - source code of the official production release `<release>`.

## How to Contribute

See [Contributing](./CONTRIBUTING.md) document for details about contribution process.

This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](./CODE_OF_CONDUCT.md) code of conduct.

### License
Intel® Cryptography Primitives Library is licensed under Apache License, Version 2.0. By contributing to the project, you agree to the license and copyright terms therein and release your contribution under these terms.

## Latest Certification

Intel® Cryptography Primitives Library is validated for FIPS-140-3 (Security Requirements for Cryptographic Modules) compliance and has the following CAVP (Cryptographic Algorithm Validation Program) certificates:

- [Intel® Cryptography Primitives Library optimized for Intel® AVX512 ISA](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=41279)
- [Intel® Crypto Multi-buffer Library optimized for Intel® AVX512 ISA](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=41280)
