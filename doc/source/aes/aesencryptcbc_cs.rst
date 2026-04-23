.. _aesencryptcbc_cs:


AESEncryptCBC_CS
================


Encrypts plaintext in the CBC ciphertext stealing mode of the AES block
cipher.


Syntax
------


IppStatus ippsAESEncryptCBC_CS1(const Ipp8u\* pSrc, Ipp8u\* pDst, int
len, const IppsAESSpec\* pCtx, const Ipp8u\* pIV);


IppStatus ippsAESEncryptCBC_CS2(const Ipp8u\* pSrc, Ipp8u\* pDst, int
len, const IppsAESSpec\* pCtx, const Ipp8u\* pIV);


IppStatus ippsAESEncryptCBC_CS3(const Ipp8u\* pSrc, Ipp8u\* pDst, int
len, const IppsAESSpec\* pCtx, const Ipp8u\* pIV);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input plaintext data of variable length.
   * - pDst
     - Pointer to the resulting ciphertext data.
   * - len
     - Length of the input data stream in bytes.
   * - pCtx
     - Pointer to the IppsAESSpec context.
   * - pIV
     - Pointer to the initialization vector for the CBC mode operation.




Description
-----------


These functions encrypt the input data stream according to the three
variants of the Cipher Block Chaining (CBC) mode with Ciphertext
Stealing (CS), as specified in
:term:`NIST SP 800-38A A. <[NIST SP 800-38A A.]>`. An
important difference of these variants from the CBC mode without CS is
that the number of bits in the input plaintext does not have to be a
multiple of the block size.


The block size is 128 bits in accordance with
:term:`FIPS PUB 197 <[FIPS PUB 197]>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr
     - For AESEncryptCBC_CS1 and AESEncryptCBC_CS2, indicates an error condition if the input data length is less than the cipher block size.
       For AESEncryptCBC_CS3, indicates an error condition if the input data length is less than or equal to the cipher block size.
   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.



