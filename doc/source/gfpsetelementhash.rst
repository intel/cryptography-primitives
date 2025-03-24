.. _gfpsetelementhash:


GFpSetElementHash
=================


Assigns a value from the input hash to an element of the finite field.


Syntax
------


IppStatus ippsGFpSetElementHash(const Ipp8u\* pMsg, int msgLen,
IppsGFpElement\* pElm, IppsGFpState\* pGF, IppHashAlgId hashID);


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
     -  Length of the input message.
   * -     pElm   
     -  Pointer to the context of the finite field element.
   * -     pGF   
     -  Pointer to the context of the finite field.
   * -     hashID   
     -  ID of the hash algorithm used. For details, see table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.




Description
-----------


This function computes an element of the finite field from the hash of
the input message.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNotSupportedModeErr   
     -  Indicates an error condition if hashID does not correspond to any supported hash ID.
   * -     ippStsNullPtrErr   
     - Indicates an error condition in one of the following cases:
       
       * Any of the pointers pElm and pGF is NULL.
       * The msgLen is greater than zero and the pointer pMsg is NULL.
       
   * -     ippStsLengthErr   
     -  Indicates an error condition if msgLen is negative.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of thepGF and pElm context parameters does not match the operation.
   * -     ippStsBadArgErr   
     -  Indicates an error condition if the finite field specified by the context pGF is not a prime finite field.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the length of the element stored in the context pElm is not equal to the length of an element of the finite field specified by the context pGF.



