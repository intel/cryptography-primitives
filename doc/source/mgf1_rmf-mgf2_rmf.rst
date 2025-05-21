.. _mgf1_rmf-mgf2_rmf:



MGF1_rmf, MGF2_rmf
==================


Generates a pseudorandom mask of the specified length using a selected
hash lagorithm based on MGF1 or MGF2 specifications.


Syntax
------


IppStatus ippsMGF1_rmf(const Ipp8u\* pSeed, int seedLen, Ipp8u\* pMask,
int maskLen, const IppsHashMethod\* pMethod);


IppStatus ippsMGF2_rmf(const Ipp8u\* pSeed, int seedLen, Ipp8u\* pMask,
int maskLen, const IppsHashMethod\* pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSeed   
     -  Pointer to the input octet string.
   * -     seedLen   
     -  Length of the input string in bytes.
   * -     pMask   
     -  Pointer to the output pseodorandom mask.
   * -     maskLen   
     -  Desired length of the output.
   * -     pMethod   
     -  Pointer to the hash method.




Description
-----------


The function generates a pseudorandom mask of the specified length using
the hash algorithm defined by pMethod, as defined in the MGF1 and MGF2
specifications. To get a value for the pMethod parameter, call one of
the :ref:`HashMethod <hashmethod>`
functions.


.. note::


   These are *reduced memory footprint* functions. To learn more, see
   :ref:`Reduced Memory Footprint Functions <one-way-hash-primitives>`.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL
   * -     ippStsLengthErr   
     -  Indicates an error condition if any of the specified lengths is negative or zero.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if the provided hash algorithm identifier is not supported.
   * -     ippStsMemAllocErr
     -  An internal functional error. If this output status appears, update to the latest version of the library or contact `Intel <https://github.com/intel/cryptography-primitives/issues>`_.



