.. _hashmessage:


HashMessage
===========


Computes the digest value of an input message.


Syntax
------


IppStatus ippsHashMessage(const Ipp8u \*pMsg, int len, Ipp8u \*pMD,
IppHashAlgId hashAlg);


IppStatus ippsHashMessage_rmf(const Ipp8u \*pMsg, int msgLen, Ipp8u
\*pHash, const ippsHashMethod \*pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pMsg
     -  Pointer to the input message.
   * -     len, msgLen
     -  Message length in octets.
   * -     pMD, pHash
     -  Pointer to the resultant digest.
   * -     hashAlg
     -  Identifier of the hash algorithm.
   * -     pMethod
     -  Pointer to the hash method.




Description
-----------

.. note::


   ippsHashMessage API is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function uses the selected hash algorithm to compute the digest
value of the entire (non-streaming) input message. The hashAlg and
pMethod parameters define the hash algorithm used. The hashAlg parameter
can take one of the values listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
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
     -      Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -     Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr
     -      Indicates an error condition if the length of the input data stream is less than zero.
   * -     ippStsNotSupportedModeErr
     -     Indicates an error condition if the hashAlg parameter does not match any value of IppHashAlg listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.




Example
-------


The code below computes MD5 digest of a message.


.. code-block:: cpp


   void MD5_sample(void)
   {
         // define message
         Ipp8u msg[] = "abcdefghijklmnopqrstuvwxyz";


         // once the whole message is placed into memory,
         // you can use the integrated primitive
         Ipp8u digest[16];
         ippsHashMessage(msg, strlen((char*)msg), digest, IPP_ALG_HASH_MD5);
   }

