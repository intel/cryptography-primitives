.. _prngenrdrand:


PRNGenRDRAND
============


Generates a pseudorandom unsigned 32-bit int buffer of the specified bit length
using the RDRAND instruction. If the last 32-bit int is not filled, its most significant
bits are zeroed.


Syntax
------


IppStatus ippsPRNGenRDRAND(Ipp32u\* pRand, int nBits, void\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pRand
     -  Pointer to the output pseudorandom unsigned integer big number.
   * -     nBits
     -  The number of generated pseudorandom bits.
   * -     pCtx
     -  Pointer to the IppsPRNGState context. This pointer is unused and can be NULL.




Description
-----------


The function generates a pseudorandom unsigned integer big number of the
specified nBits length. The generation is based on the RDRAND
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
     -  Indicates an error condition if pRand is NULL.
   * -     ippStsErr
     -  Indicates an error condition if the random bit sequence can't be generated.
   * -     ippStsLengthErr
     -  Indicates an error condition if nBits is less than 1.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if the RDRAND instruction is not available on the target processor.



