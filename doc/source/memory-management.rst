.. _memory-management:

Memory Management
=================

Intel® Cryptography Primitives Library is implemented in C and follows standard C memory management practices. 
**It is the caller's responsibility to ensure all memory buffers are properly allocated, sized and released.**

Buffer Requirements
-------------------

All input and output buffers must be allocated with the correct size as specified by the algorithm parameters and API documentation. 
The library does not verify the actual size of memory pointed to by buffer parameters.

Determining Buffer Sizes
------------------------

Use the corresponding size query functions to determine required buffer sizes:

- **Context Size Functions**: :samp:`{<algorithm>}_GetSize()` 
- **Buffer Size Functions**: :samp:`{<algorithm>}_<operation>BufferGetSize()`
- **Information Functions**: :samp:`{<algorithm>}_GetInfo()`

Example usage:

.. code-block:: c

   int ctxSize = 0;
   
   // Query required context size in bytes
   ippsAESGetSize(&ctxSize);
   
   // Allocate with correct size
   IppsAESSpec* pCtx = (IppsAESSpec*)malloc(ctxSize);
   
   // ... use the context ...
   
   // Release memory
   free(pCtx);

Application Responsibilities
----------------------------

Applications must allocate sufficient memory before passing pointers to library functions and implement additional input validation 
if required by compliance standards.
