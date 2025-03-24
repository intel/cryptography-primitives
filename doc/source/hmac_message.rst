.. _hmac_message:


HMAC_Message
============


Computes the HMAC value of an entire message.


Syntax
------


IppStatus ippsHMAC_Message(const Ipp8u \*pMsg, int msgLen, const Ipp8u
\*pKey, int keyLen, Ipp8u \*pMD, int mdLen, IppHashAlgId hashAlg);


IppStatus ippsHMACMessage_rmf(const Ipp8u \*pMsg, int msgLen, const
Ipp8u \*pKey, int keyLen, Ipp8u \*pMAC, int macLen, const ippsHashMethod
\*pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pMsg   
     -  Pointer to the input message.
   * -     msgLen   
     -  Message length in bytes.
   * -     pKey   
     -  Pointer to the user-supplied key.
   * -     keyLen   
     -  Key length in bytes.
   * -     pMD, pMAC   
     -  Pointer to the resultant HMAC value.
   * -     mdLen, macLen   
     -  Specified HMAC length.
   * -     hashAlg   
     -  Identifier of the hash algorithm.
   * -     pMethod   
     -  Pointer to the hash method.




Description
-----------


The function takes the input secret key pKey of the specified key length
keyLen and applies the keyed hash-based message authentication code
scheme to transform the input message into the respective message
authentication code pMD or pMAC of the specified length mdLen or macLen.
The hashAlg and pMethod parameters define the hash algorithm applied.
The hashAlg parameter can take one of the values listed in table
:ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
To get a value for the pMethod parameter, call one of the
:ref:`HashMethod <hashmethod>`
functions.


.. note::


   This function has a *reduced memory footprint* version. To learn
   more, see :ref:`Reduced Memory Footprint Functions <one-way-hash-primitives>`.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -     Indicates no error. Any other value indicates an error or warning.   
   * -     ippStsNullPtrErr   
     -      Indicates an error condition if any of the specified pointers is NULL.   
   * -     ippStsLengthErr   
     - Indicates an error condition if:
       
       * ``msgLen`` is less than zero
       * ``mdLen`` is less than one or greater than the length of the hash value
       * ``macLen`` is less than one or greater than the length of the hash value
       
   * -     ippsStsNotSupportedModeErr   
     -     Indicates an error condition if the hashAlg parameter does not match any value of IppHashAlg listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.   



