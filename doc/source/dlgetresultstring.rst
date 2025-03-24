.. _dlgetresultstring:

DLGetResultString
=================


For DL-based cryptosystems, returns the character string corresponding
to code that represents the result of validation.


Syntax
------


const char\* ippsDLGetResultString(IppDLResult code);


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


For DL-based cryptosystems, the function returns the character string
corresponding to code that represents the result of validation.


Return Values
-------------


Possible values of code and the corresponding character strings are as
follows:


.. list-table:: 
   :header-rows: 0

   * - default    
     - "Unknown DL result"
   * - ippDLValid   
     - "Validation passed successfully"
   * - ippDLBaseIsEven   
     - "Base is even"
   * - ippDLOrderIsEven   
     - "Order is even"
   * - ippDLInvalidBaseRange   
     - "Invalid Base (``P``) range"
   * - ippDLInvalidOrderRange   
     - Invalid Order (``R``) range"
   * - ippDLCompositeBase   
     - "Composite Base (``P``)"
   * - ippDLCompositeOrder   
     - "Composite Order (``R``)"
   * - ippDLInvalidCofactor   
     - "``R`` does not divide (``P`` -1)"
   * - ippDLInvalidGenerator   
     - "1 != ``G``\ ^\ ``R`` (mod ``P``)"
   * - ippDLInvalidPrivateKey   
     - "Invalid Private Key"
   * - ippDLInvalidPublicKey   
     - "Invalid Public Key"
   * - ippDLInvalidKeyPair   
     - "Invalid Key Pair"
   * - ippDLInvalidSignature   
     - "Invalid Signature"


.. rubric:: Related Information

* :ref:`dlpvalidatedh`
* :ref:`dlpvalidatedsa`
* :ref:`dlpvalidatekeypair`
