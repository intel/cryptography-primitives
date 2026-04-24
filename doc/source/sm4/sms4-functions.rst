.. _sms4-functions:



SMS4 Functions
==============


You can use the functions described in this section for various
operational modes of SMS4 cipher systems
:term:`SMS4 <[SMS4]>`.


Intel® Cryptography Primitives Library supports ECB, CBC, CFB, CTR, and OFB modes.
You can tell which algorithm a given function supports from the function
base name, for example, the
:ref:`SMS4EncryptECB <sms4encryptecb>`
function operates under the ECB mode.


All functions for the SMS4 block cipher use the context IppsSMS4Spec,
which serves as an operational vehicle to carry the material required
for various modes of operation.


Application code for conducting a typical encryption under the CBC mode
using the SMS4 scheme must perform the following sequence of operations:


#. Get the size required to configure the context IppsSMS4Spec by
   calling the function
   :ref:`SMS4GetSize <sms4getsize>`.
#. Call an operating system memory allocation service function to
   allocate a buffer of size not less than the one specified by the
   function SMS4GetSize.
#. Initialize the pointer to the context by calling the function
   :ref:`SMS4Init <sms4init>`.
#. Specify the initialization vector and then call the function
   :ref:`SMS4EncryptCBC <sms4encryptcbc>`
   to encrypt the input data stream under CBC mode using SMS4 scheme.
#. Clean up secret data stored in the context.
#. Free the memory allocated to the buffer once SMS4 encryption under
   the CBC mode has been completed.


.. note::


   You can apply a similar procedure to ECB, CFB, CTR, and OFB modes of
   operation.


   A similar scheme also holds for decryption.


.. rubric:: Related Information

:ref:`data-security-considerations`



.. toctree::
   :maxdepth: 1


   sms4getsize
   sms4init
   sms4setkey
   sms4encryptecb
   sms4decryptecb
   sms4encryptcbc
   sms4decryptcbc
   sms4encryptcbc_cs
   sms4decryptcbc_cs
   sms4encryptcfb
   sms4decryptcfb
   sms4encryptofb
   sms4decryptofb
   sms4encryptctr
   sms4decryptctr
