.. _gfpecinitstd:


GFpECInitStd
============


Initializes the context for the cryptosystem based on a standard
elliptic curve.


Syntax
------


IppStatus ippsGFpECInitStd128r1(const IppsGFpState\* pGFp,
IppsGFpECState\* pEC);


IppStatus ippsGFpECInitStd128r2(const IppsGFpState\* pGFp,
IppsGFpECState\* pEC);


IppStatus ippsGFpECInitStd192r1(const IppsGFpState\* pGFp,
IppsGFpECState\* pEC);


IppStatus ippsGFpECInitStd224r1(const IppsGFpState\* pGFp,
IppsGFpECState\* pEC);


IppStatus ippsGFpECInitStd256r1(const IppsGFpState\* pGFp,
IppsGFpECState\* pEC);


IppStatus ippsGFpECInitStd384r1(const IppsGFpState\* pGFp,
IppsGFpECState\* pEC);


IppStatus ippsGFpECInitStd521r1(const IppsGFpState\* pGFp,
IppsGFpECState\* pEC);


IppStatus ippsGFpECInitStdSM2(const IppsGFpState\* pGFp,
IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pGFp
     - Pointer to the IppsGFpState context of the underlying finite field.
   * - pEC
     - Pointer to the cryptosystem context based on a standard elliptic curve




Description
-----------


Each of these functions initializes the context of the elliptic curve
cryptosystem based on a specific standard elliptic curve. For a list of
these curves, see table :ref:`Standard Elliptic
Curves <arithmetic-of-the-group-of-elliptic-curve-points>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the IppsGFpECState context parameter does not match the operation.
   * - ippStsBadArgErr
     - Indicates an error condition if the IppsGFpECState context parameterdoes not specify the finite field over which the givenstandard elliptic curve is defined.



