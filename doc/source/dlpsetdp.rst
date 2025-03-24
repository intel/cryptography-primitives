.. _dlpsetdp:


DLPSetDP
========


Sets up a particular domain parameter of the DL-based cryptosystem over
GF(p).


Syntax
------


IppStatus ippsDLPSetDP(const IppsBigNumState\* pDP, IppDLPKeyTag tag,
IppsDLPState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pDP   
     - Pointer to the domain parameter value to be set.
   * - tag   
     - Tag specifying the desired domain parameter.
   * - pCtx   
     - Pointer to the cryptosystem context.




Description
-----------


The function assigns the value specified by pDP to a particular domain
parameter of the DL-based cryptosystem. The domain parameter to be set
up is determined by tag as follows:


-  If tag == IppDLPkeyP, the function assigns value to the
   characteristic *p*, the size of the prime finite field GF(p).
-  If tag == IppDLPkeyR, the function assigns value to the
   characteristic r, the prime divisor of (*p*-1) and the order of *g.*
-  If tag == IppDLPkeyG, the function assigns value to the
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
   * - ippStsRangeErr   
     - Indicates an error condition if the Big Number specified by pDP is too big to be stored in the IppsDLPState context.
   * - ippStsBadArgErr   
     - Indicates an error condition if some of the function parameters are invalid:
     
       * Big Number specified by pDP is negative.
       * Domain parameter specified by tag does not match the IppsDLPState context.



