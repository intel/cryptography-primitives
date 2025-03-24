.. _mbx_exp_buffersize:



mbx_exp_BufferSize
==================


Returns minimal size of work buffer requested for modular
exponentiation.


Syntax
------


int mbx_exp_BufferSize(int mod_bits);


Include Files
-------------


``crypto_mb/exp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     mod_bits   
     -  Size of modulus in bits.




Description
-----------


The function returns minimal size of work buffer requested for 1Kb, 2Kb,
3Kb or 4Kb modular exponentiation depending on mod_bits parameter. If
the mod_bits parameter does not match the supported range of modulo
size, it returns 0.

