.. _montset:


MontSet
=======


Sets the input integer big number to a value and computes the Montgomery
reduction index.


Syntax
------


IppStatus ippsMontSet(const Ipp32u \*pModulo, int size, IppsMontState
\*pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pModulo   
     -  Pointer to the input big number modulus.
   * -     size   
     -  The size of the modulus in Ipp32u chunks.
   * -     pCtx   
     -  Pointer to the context IppsMontState capturing the modulus and the least significant word of the multiplicative inverse ``Ni``.




Description
-----------


The function sets the input positive integer big number pModulo to be
the modulus for the context IppsMontState \*pCtx, computes the
Montgomery reduction index k with respect to the input big number
modulus pModulo and the least significant 32-bit word of the
multiplicative inverse ``Ni`` with respect to the modulus R, that
satisfies R\*R\ :sup:`-1`- pModulo \*\ ``Ni`` = 1.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsBadModulusErr   
     -  Indicates an error condition if the modulus is not a positive odd integer.
   * -     ippStsLengthErr   
     -  Indicates an error condition if size is less than or equal to 0.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if size is larger than IppsMontState\*pCtx.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if pCtx does not match the operation.



