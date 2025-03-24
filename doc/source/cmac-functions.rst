.. _cmac-functions:

CMAC Functions
==============


The Intel® Cryptography Primitives Library CMAC primitive functions use CMAC schemes based on block
ciphers described in the :ref:`Symmetric Cryptography Primitive
Functions <symmetric-cryptography-primitive-functions>`.


A CMAC scheme is implemented as a set of primitive functions.


Typical application code for computing CMAC of an input message stream
should follow the sequence of operations as outlined below:


#. Call the function
   :ref:`AES_CMACGetSize <aes_cmacgetsize>`
   to get the size required to configure the IppsAES_CMACState context.


#. Ensure that the required memory space is properly allocated. With the
   allocated memory, call the function
   :ref:`AES_CMACInit <aes_cmacinit>`
   to initialize the context.


#. Keep calling the function
   :ref:`AES_CMACUpdate <aes_cmacupdate>`
   to update the MAC value of the incoming message stream in the queue
   till its completion. To determine the current MAC value, call
   :ref:`AES_CMACGetTag <aes_cmacgettag>`
   between each two calls to AES_CMACUpdate.


#. Call the function
   :ref:`AES_CMACFinal <aes_cmacfinal>`
   to complete computation of the MAC value of the streaming message and
   prepare the context for computation of MAC of another message.


#. Clean up secret data stored in the context.


#. Call the operating system memory free service function to release the
   IppsAES_CMACState context.

.. toctree::
   :maxdepth: 1


   aes_cmacgetsize
   aes_cmacinit
   aes_cmacupdate
   aes_cmacfinal
   aes_cmacgettag