.. _hashinit:


HashInit
========


Initializes user-supplied memory as IppsHashState or IppsHashState_rmf
context for future use.


Syntax
------


IppStatus ippsHashInit(IppsHashState\* pCtx, IppHashAlgId hashAlg);


IppStatus ippsHashInit_rmf(IppsHashState_rmf\* pCtx, IppsHashMethod\*
pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pCtx
     -  Pointer to the IppsHashState or IppsHashState_rmf context being initialized.
   * -     hashAlg
     -  Identifier of the hash algorithm.
   * -     pMethod
     -  Pointer to the hash method.




Description
-----------

.. note::


   ippsHashInit function is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function initializes the memory pointed by pCtx as IppsHashState or
IppsHashState_rmf context. The hashAlg and pMethod parameters define the
hash algorithm to be used in subsequent calls to
:ref:`HashUpdate <hashupdate>`
,
:ref:`HashFinal <hashfinal>`,
or
:ref:`HashGetTag <hashgettag>`
functions. The hashAlg parameter can take one of the values listed in
table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
To get a value for the pMethod parameter, call one of the
:ref:`HashMethod <hashmethod>`
functions.


.. note::


   This function has a *reduced memory footprint* version. To learn
   more, see :ref:`Reduced Memory Footprint Functions <one-way-hash-primitives>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -     Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -     Indicates an error condition if any of the specified pointers is NULL or pMethod is not initialized.
           This return status can also correspond to an internal functional error. If this output status appears,
           update to the latest version of the library or contact `Intel <https://github.com/intel/cryptography-primitives/issues>`_.
   * -     ippStsNotSupportedModeErr
     -     Indicates an error condition if the hashAlg parameter does not match any value of IppHashAlg listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.




.. rubric:: Related Information

:ref:`data-security-considerations`
