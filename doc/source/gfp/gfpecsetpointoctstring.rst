.. _gfpecsetpointoctstring:



GFpECSetPointOctString
======================


Sets the coordinates of a point on an elliptic curve defined over GF(p).


Syntax
------


IppStatus ippsGFpECSetPointOctString(const Ipp8u\* pStr, int strLen,
IppsGFpECPoint\* pPoint, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pStr
     - Pointer octet string containing ``X`` and ``Y`` coordinates of the point on the elliptic curve.
   * - strLen
     - Length of the input pStr string, in bytes.
   * - pPoint
     - Pointer to the context of the elliptic curve point.
   * - pEC
     - Pointer to the context of the elliptic cryptosystem.




Description
-----------


This function sets the coordinates of a point on the elliptic curve
defined over a prime finite field GF(``p``). The input data is the octet
string containing the pair (``X``, ``Y``) of coordinates. The left half
of the pStr string represents an ``X``-coordinate and the right half
represents a ``Y``-coordinate.The left byte in ``X`` and ``Y``
representations corresponds to the most significant byte of coordinates.
The length of each part equals the length of the GF(``p``) field element
in bytes. Before using this function, you need to:


-  Define the elliptic curve domain parameters using the
   :ref:`GFpECSet <gfpecset>` or
   :ref:`GFpECSetStd <gfpecset>` and
   :ref:`GFpECSetSubgroup <gfpecsetsubgroup>`
   functions


-  Create the context of the point on the elliptic curve using the
   :ref:`GFpECPointGetSize <gfpecpointgetsize>`
   and
   :ref:`GFpECPointInit <gfpecpointinit>`
   functions


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error when any of the specified pointers is NULL.
   * - ippStsContextMatchErr
     - Indicates an error when one of the contexts pointed bypPoint orpEC is not valid or not a definedsubgroup.
   * - ippStsNotSupportedModeErr
     - Indicates an error when the finite field over which the elliptic curve is initialized is not prime.



