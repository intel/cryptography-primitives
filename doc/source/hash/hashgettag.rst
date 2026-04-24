.. _hashgettag:




HashGetTag
==========


Computes the current digest value of the processed part of the message.


Syntax
------


IppStatus ippsHashGetTag(Ipp8u\* pTag, int tagLen, const IppsHashState\*
pCtx);


IppStatus ippsHashGetTag_rmf(Ipp8u\* pTag, int tagLen,
ippsHashState_rmf\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pTag
     -  Pointer to the authentication tag.
   * -     tagLen
     -  The length of the tag (in bytes).
   * -     pCtx
     -  Pointer to the IppsHashState or IppsHashState_rmf context.




Description
-----------

.. note::


   ippsHashGetTag function is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function computes the message digest based on the current context as
specified in :term:`FIPS PUB 180-2 <[FIPS PUB 180-2]>`,
:term:`FIPS PUB 180-4 <[FIPS PUB 180-4]>` and
:term:`RFC 1321 <[RFC 1321]>`.
A call to this function retains the possibility to update the digest.


.. note::


   This function has a *reduced memory footprint* version. To learn
   more, see :ref:`Reduced Memory Footprint Functions <one-way-hash-primitives>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr
     -  Indicates an error condition if tagLen < 1 or tagLen exceeds the maximal length of a particular digest.
   * -     ippStsContextMatchErr
     -  Indicates an error condition if the context parameter does not match the operation.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if the provided hash algorithm identifier is not supported.



