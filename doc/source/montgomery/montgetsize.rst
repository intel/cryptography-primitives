.. _montgetsize:

MontGetSize
===========


Gets the size of the IppsMontState context.


Syntax
------


IppStatus ippsMontGetSize(IppsExpMethod method, int length, int \*
pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     method   
     -  Selected exponential method.
   * -     length   
     -  Data field length for the modulus in Ipp32u chunks.
   * -     pSize   
     -  Pointer to the size of the buffer required for initialization.




Description
-----------


The function specifies the buffer size required to define the structured
working buffer of the context IppsMontState to store the modulus and
perform operations using various Montgomery modulus schemes.


.. note::


   For security reasons, the length of the modulus is restricted to 16
   kilobits.


The function returns the required buffer size based on the selected
exponential method. The binary method helps to significantly reduce the
buffer size, while the sliding windows method results in enhanced
performance.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     -  Indicates an error condition if length is less than or equal to 0 or greater than 512.



