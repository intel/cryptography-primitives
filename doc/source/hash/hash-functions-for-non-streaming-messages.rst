.. _hash-functions-for-non-streaming-messages:



Hash Functions for Non-Streaming Messages
=========================================


This section describes functions that calculate a digest of an entire
(non-streaming) input message by applying a selected hash algorithm, as
well as a possibility to use a different implementation of a hash
algorithm.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   The crypto community does not consider SHA-1 or MD5 algorithms secure
   anymore.


   Recommendation: use a more secure hash algorithm (for example, any
   algorithm from the SHA-2 family) instead of SHA-1 or MD5.

.. toctree::
   :maxdepth: 1

   
   general-definition-of-a-hash-function
   hashmessage