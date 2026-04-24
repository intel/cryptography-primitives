.. _montinit:



MontInit
========


Initializes the context and partitions the specified buffer space.


Syntax
------


IppStatus ippsMontInit(IppsExpMethod method, int length, IppsMontState
\*pCtx);


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
   * -     pCtx   
     -  Pointer to the context IppsMontState.




Description
-----------


The function initializes the \*pCtx buffer as the IppsMontState context.
The function then partitions the buffer using the selected modular
exponential method in such a way as to carry up to
length\*sizeof(Ipp32u)-bit big number modulus and execute various
Montgomery modulus operations.


.. note::


   For security reasons, the length of the modulus is restricted to 16
   kilobits.


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



.. rubric:: Related Information

:ref:`data-security-considerations`

