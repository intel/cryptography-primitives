.. _trngenrdseed_bn:



TRNGenRDSEED_BN
===============


Generates a true random positive Big Number of the specified bit length
using the RDSEED instruction.


Syntax
------


IppStatus ippsTRNGenRDSEED_BN(IppsBigNumState\* pRand, int nBits, void\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pRand
     -  Pointer to the output true random Big Number.
   * -     nBits
     -  The number of generated true random bits.
   * -     pCtx
     -  Pointer to the IppsPRNGState context. This pointer is unused and can be NULL.




Description
-----------


The function generates a true random positive Big Number of the
specified nBits length. The generation is based on the RDSEED
instruction available on latest Intel® processors
:term:`INTEL_ARCH <[INTEL ARCH]>`.


.. admonition:: Product and Performance Information

   Performance varies by use, configuration and other factors. Learn more at https://edc.intel.com/content/www/us/en/products/performance/benchmarks/overview/.
   Notice revision #20201201


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -  Indicates an error condition if the context parameter does not match the operation.
   * -     ippStsLengthErr
     -  Indicates an error condition if nBits is less than 1.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if the RDSEED instruction is not available on the target processor.



