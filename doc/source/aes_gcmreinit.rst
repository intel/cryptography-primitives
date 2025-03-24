.. aes_gcmreinit:

AES_GCMReinit
=============

Re-initializes user-provided ``IppsAES_GCMState`` for future usage. The function updates the internal ``IppsAES_GCMState`` structure’s pointers only, the intermediate state of the context is unchanged.

Syntax
******

IppStatus ippsAES_GCMReinit(IppsAES_GCMState * pState)

Include Files
*************

ippcp.h

Parameters
**********

.. list-table:: 
   :header-rows: 0

   * - pState  
     - Pointer to the ``IppsAES_GCMState`` context being reinitialized.


Description
***********

This function:

* Accepts a pointer to the ``IppsAES_GCMState`` context that is proceeded with the ``ippsAES_GCMInit`` function before.
* Updates stored inside the context’s internal pointers. 
  
It may be useful when the context physically lies in the same memory, but its virtual high-level address is changed - some pointers inside become stale, and can point to illegal memory. 
Therefore, it needs to be re-initialized.

.. note:: The use case of this API is very specific. It should not be used to re-initialize a context that is copied from original context. Computations in this case may be incorrect. 


Return Values
*************

.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if ``IppsAES_GCMState`` pointer is NULL.


