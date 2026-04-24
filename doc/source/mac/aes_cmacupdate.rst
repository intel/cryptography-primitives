.. _aes_cmacupdate:


AES_CMACUpdate
==============


Updates the MAC value depending on the current input message stream of
the specified length.


Syntax
------


IppStatus ippsAES_CMACUpdate(const Ipp8u \*pSrc, int len,
IppsAES_CMACState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pSrc    
     - Pointer to the buffer containing a part or the entire message.
   * - len   
     - Length of the actual part of the message in bytes.
   * - pState   
     - Pointer to the IppsAES_CMACState context.




Description
-----------


The function updates the MAC value depending on the current input
message stream of the specified length. The function first integrates
the previous partial message block with the input message stream and
then partitions the obtained message into multiple message blocks with a
possible additional partial block. For each message block, the function
uses the AES cipher to transform the input block into a new chaining MAC
value.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr   
     - Indicates an error condition if the input data stream length is less than zero.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the context parameter does not match the operation.



