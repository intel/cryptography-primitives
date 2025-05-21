.. _gfpecsetpointhash-bkcomp-hash_rmf-bkcomp_rmf:


GFpECSetPointHash, GFpECSetPointHashBackCompatible, GFpECSetPointHash_rmf, GFpECSetPointHashBackCompatible_rmf
==============================================================================================================


Constructs a point on an elliptic curve based on the hash of the input
message.


Syntax
------


IppStatus ippsGFpECSetPointHash(Ipp32u hdr, const Ipp8u\* pMsg, int
msgLen, IppsGFpECPoint\* pPoint, IppsGFpECState\* pEC, IppHashAlgId
hashID, Ipp8u\* pScratchBuffer);


IppStatus ippsGFpECSetPointHash_rmf(Ipp32u hdr, const Ipp8u\* pMsg, int
msgLen, IppsGFpECPoint\* pPoint, IppsGFpECState\* pEC, const
IppsHashMethod\* pMethod, Ipp8u\* pScratchBuffer);


IppStatus ippsGFpECSetPointHashBackCompatible(Ipp32u hdr, const Ipp8u\*
pMsg, int msgLen, IppsGFpECPoint\* pPoint, IppsGFpECState\* pEC,
IppHashAlgId hashID , Ipp8u\* pScratchBuffer);


IppStatus ippsGFpECSetPointHashBackCompatible_rmf(Ipp32u hdr, const
Ipp8u\* pMsg, int msgLen, IppsGFpECPoint\* pPoint, IppsGFpECState\* pEC,
const IppsHashMethod\* pMethod, Ipp8u\* pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - hdr
     - Header of the input message.
   * - pMsg
     - Pointer to the input message.
   * - msgLen
     - Length of the input message.
   * - pPoint
     - Pointer to the IppsGFpECPoint context.
   * - pEC
     - Pointer to the context of the elliptic curve.
   * - hashID
     - ID of the hash algorithm used. For details, see :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
   * - pMethod
     - Predefined Hash Algorithm method. For details, see :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
   * - pScratchBuffer
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


This function makes the coordinates of a point on the elliptic curve
over the finite field from a hash of the ``X``-coordinate. 

The ``X``-coordinate is computed by the following pseudocode formula:
``X = hash(hdr || message)``.

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 1 to get the valid *pScratchBuffer*.

Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition in the following cases:

        * ``pPoint`` or pEC is NULL.
        * Length of the message is more than zero, and the pointer pMsg is NULL.

   * -     ippStsContextMatchErr
     -  Indicates an error condition if either pPoint or pEC context parameter does not match the operation.
   * -     ippStsBadArgErr
     -  Indicates an error condition if the finite field over which the elliptic curve is initialized is not prime.
   * -     ippStsOutOfRangeErr
     -  Indicates an error condition if the coordinates of the point pPoint do not belong to the finite field over which the elliptic curve is initialized.
   * -     ippStsLengthErr
     -  Indicates an error condition if msgLen is negative.
   * -     ippStsQuadraticNonResidueErr
     -  Indicates an error condition if the square of the ``Y``-coordinate of the point is a quadratic non-residue modulo ``p``.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if the provided hash algorithm identifier is not supported.
   * -     ippStsMemAllocErr
     -  An internal functional error. If this output status appears, update to the latest version of the library or contact `Intel <https://github.com/intel/cryptography-primitives/issues>`_.



