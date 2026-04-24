.. _mbx_rsa_method_bufsize:



mbx_RSA_Method_BufSize
======================


Returns the size of a work buffer for a specific RSA operation.


Syntax
------


int mbx_RSA_Method_BufSize(const mbx_RSA_Method\*m);


Include Files
-------------


``crypto_mb/rsa.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -      m   
     -  Pointer to the pre-defined data structure specified by the RSA encryption operation.




Description
-----------


The mbx_RSA_Method_BufSize() function returns the size of a work buffer
in bytes required for the RSA operation specified by the parameter m. If
m is ``NULL``, the function returns 0.

