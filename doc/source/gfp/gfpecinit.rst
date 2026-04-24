.. _gfpecinit:


GFpECInit
=========


Initializes the context of an elliptic curve over a finite field.


Syntax
------


IppStatus ippsGFpECInit(const IppsGFpState\* pGF, const IppsGFpElement\*
pA, const IppsGFpElement\* pB, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pGF   
     - Pointer to the IppsGFpState context of the underlying finite field.
   * - pA   
     - Pointer to the coefficient ``A`` of the equation defining the elliptic curve.
   * - pB   
     - Pointer to the coefficient ``B`` of the equation defining the elliptic curve.
   * - pEC   
     - Pointer to the context of the elliptic curve being initialized.




Description
-----------


This function initializes the memory buffer pEC associated with the
IppsGFpECState context and sets up the parameters of the elliptic curve
if they are supplied. The initialized context is used in functions that
create contexts of points on the curve (elements of the group of points)
and perform operations with the points.


.. note::


   Only the ``pEC`` and ``pGF`` parameters are required. You can omit the other
   parameters by setting their values to NULL or zero and set them up
   later on by calling ``GFpECSet`` or ``GFpECSetSubGroup``.


.. note::


   When calling arithmetic functions for the elliptic curve defined
   by ``pEC``, a properly initialized ``pGF`` context of the underlying field is
   required.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if either pEC or pGF is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition in the following cases:
       
       * ``IppsGFpState`` context parameter does not match the operation.
       * ``pA`` or ``pB`` is not zero and the corresponding context parameter does not match the operation.



