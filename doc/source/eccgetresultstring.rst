.. _eccgetresultstring:

ECCGetResultString
==================


For elliptic curve cryptosystems, returns the character string
corresponding to code that represents the result of validation.


Syntax
------


const char\* ippsECCGetResultString(IppECResult code);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - code   
     - The code of the validation result.




Description
-----------


For elliptic curve cryptosystems, returns the character string
corresponding to code that represents the result of validation.


Return Values
-------------


Possible values of code and the corresponding character strings are as
follows:


.. list-table:: 
   :header-rows: 0

   * - default    
     - "Unknown ECC result"
   * - ippECValid   
     - "Validation passed successfully"
   * - ippECCompositeBase   
     - "Finite Field produced by Composite"
   * - ippECComplicatedBase   
     - "Too many non-zero terms in the polynomial"
   * - ippECIsZeroDiscriminant   
     - "Zero discriminant"
   * - ippECCompositeOrder   
     - "Composite Base Point order"   
   * - ippECInvalidOrder   
     - "Composite Base Point order"   
   * - ippECIsWeakMOV   
     - "EC cover by MOV Reduction Test"
   * - ippECIsWeakSSSA   
     - "EC cover by SS-SA Reduction Test"   
   * - ippECIsSupersingular   
     - "EC is supersingular curve"
   * - ippECInvalidPrivateKey   
     - "Invalid Private Key"
   * - ippECInvalidPublicKey   
     - "Invalid Public Key"
   * - ippECInvalidKeyPair   
     - "Invalid Key Pair"
   * - ippECPointOutOfGroup   
     - "Point is out of group"   
   * - ippECPointAtInfinite   
     - "Point at infinity"
   * - ippECPointIsNotValid   
     - "Invalid EC Point"   
   * - ippECPointIsEqual   
     - "Points are equal"
   * - ippECPointIsNotEqual   
     - "Points are different"
   * - ippECInvalidSignature   
     - "Invalid Signature"


.. rubric:: Related Information

* :ref:`gfpecverify`
* :ref:`gfpectstkeypair`

