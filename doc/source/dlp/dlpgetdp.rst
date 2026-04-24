.. _dlpgetdp:


DLPGetDP
========


Retrieves a particular domain parameter of the DL-based cryptosystem
over GF(p).


Syntax
------


IppStatus ippsDLPGetDP(IppsBigNumState\* pDP, IppDLPKeyTag tag, const
IppsDLPState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pDP   
     - Pointer to the output Big Number context.
   * - tag   
     - Tag specifying the domain parameter to be retrieved.
   * - pCtx   
     - Pointer to the cryptosystem context.




Description
-----------


The function retrieves value of a particular domain parameter of the
DL-based cryptosystem from the IppsDLPState context and stores the value
in the Big Number context \*pDP. The domain parameter to be retrieved is
determined by tag as follows:


-  If tag == IppDLPkeyP, the function retrieves value of the
   characteristic *p*, the size of the prime finite field GF(p).
-  If tag == IppDLPkeyR, the function retrieves value of the
   characteristic r, the prime divisor of (*p*-1) and the order of *g.*
-  If tag == IppDLPkeyG, the function retrieves value of the
   characteristic *g,* the element of GF(*p*) generating a
   multiplicative subgroup of order *r.*


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the context parameter does not match the operation.
   * - ippStsIncompleteContextErr    
     - Indicates an error condition if the cryptosystem context has not been properly set up.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if the Big Number specified by pDP is too small for the DL parameter.
   * - ippStsBadArgErr   
     - Indicates an error condition if the domain parameter specified by the tag does not match the IppsDLPState context.



