.. _gfpecgetpointoctstring:


GFpECGetPointOctString
======================


Retrieves coordinates of a point on an elliptic curve defined over
GF(p).


Syntax
------


IppStatus ippsGFpECGetPointOctString(const IppsGFpECPointState\* pPoint,
Ipps8u\* pStr, int lenStr, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pPoint
     - Pointer to the context of the elliptic curve point.
   * - pStr
     - Pointer to the target string of octets.
   * - lenStr
     - Available length of pStr, in bytes.
   * - pEC
     - Pointer to the context of the elliptic curve cryptosystem.




Description
-----------


This function retrieves the coordinates of pPoint on the pEC elliptic
curve from the point context, converts each ``X`` and ``Y`` coordinate
into the octet string and stores them in pStrso so that the left half contains
``X`` and the right half contains ``Y`` point's coordinate. Before using
this function, define the elliptic curve domain parameters using the following
function: :ref:`GFpECSetSubgroup <gfpecsetsubgroup>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error when pPoint or pEC is NULL.
   * - ippStsContextMatchErr
     - Indicates an error when one of the contexts pointed bypPoint orpEC is not valid or not a definedsubgroup.
   * - ippStsNotSupportedModeErr
     - Indicates an error when the finite field over which the elliptic curve is initialized is not prime.
   * - ippStsOutOfRangeErr
     - Indicates an error when the size of a point coordinate is not equal to the size of the GF(``p``) element.
   * - ippStsSizeErr
     - Indicates an error when strLen != 2\*gfelementLen, where gfelementLen is the size of the GF(``p``) element.



