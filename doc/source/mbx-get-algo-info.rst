.. _mbx-get-algo-info:


mbx_get_algo_info
=================

Queries the number of parallel buffers supported for the specified algorithm.


Syntax
------

MBX_ALGO_INFO mbx_get_algo_info(enum MBX_ALGO algo);


Include Files
-------------

``crypto_mb/cpu_features.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - algo   
     - ``MBX_ALGO`` element specifying the algorithm of interest.


Description
-----------

The ``mbx_get_algo_info()`` function queries in runtime the number of parallel
buffers that is processed by the specified algorithm and can be used to check if
the algorithm is enabled for the current CPU.


Return Values
-------------
``MBX_ALGO_INFO`` value which is number of parallel buffers supported for the specified algorithm
or ``0`` if it is not supported for the current CPU.
