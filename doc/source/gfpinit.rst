.. _gfpinit:



GFpInit
=======


Initializes the context of a prime finite field GF(q).


Syntax
------


IppStatus ippsGFpInit(const IppsBigNumState\* pPrime, int primeBitSize,
const IppsGFpMethod\* method, IppsGFpState\* pGF);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pPrime   
     -  Pointer to the Big Number context storing the GF(``q``) modulus.
   * -     primeBitSize   
     -  Size, in bytes, of the odd prime number ``p`` (modulus of GF(``q``)).
   * -     method   
     -  Pointer to the implementation of a basic arithmetic (methods) over the prime finite field GF(``q``).
   * -     pGF   
     -  Pointer to the context of the GF(``q``) field being initialized.


.. note:: If your application uses one of predefined values of the modulus q, the use of the GFpMethod function corresponding to that value is preferable. In other cases, use ``ippsGfpMethod_pArb()``.


Description
-----------


The function initializes the pGF context parameter with the values of
the input parameterspPrime, primeBitSize, and method. The three
parameters have to be compatible with each other.


The method parameter must be an output from one of the
:ref:`GFpMethod <gfpmethod>` functions
with predefined modulus ``q``, and the parameters primeBitSize and
method must be compatible with each other.


If pPrime is not NULL, and method is an output from one of the GFpMethod
functions with predefined modulus ``q``, then the pair pPrime and
primeBitSize should define the same prime ``q`` as defined in method.


If both pPrime and method are not NULL, then ippsGFpInit() provides the
required initialization if the parameters are compatible with each
other.


The initialized context is used in the functions that create contexts of
elements of the GF(``p``) field, which, in turn, are used to perform
operations with the field elements.


.. note::


   This function does not check if pPrime actually refers to a prime
   value.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition in the following cases:
     
        * pGF is NULL.
        * Both pPrime and method are NULL.
        
   * -     ippStsSizeErr   
     -  Indicates an error condition if primeBitSize is less than 2 or greater than 1024.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the pPrime context parameter is not NULL and does not match the operation.
   * -     ippStsBadArgErr   
     -  Indicates an error condition in the following cases:
        
        * The modulus q defined in pPrime is less than 3.
        * bitsize(q) != primeBitSize.
        * q is even.
        * method is not NULL and not an output of ``GFpMethod``.
        * method is an output from one of the ``GFpMethod`` functions with predefined modulus q, but:
          
          * The bit size of q of method is different from the bit size of the value stored in the context pointed to by pPrime.
          * q of method is different from the value stored in the context pointed to by pPrime.



