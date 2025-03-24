.. _data-security-considerations:


Data Security Considerations
============================


Intel® Cryptography Primitives Library functions use several types of buffers during
operation, and some of them may contain sensitive information. These
buffers may be reused multiple times, and there is no way for the
underlying Intel® Cryptography Primitives Library implementation to know when this data is no longer
needed and sensitive information should be scrubbed from those buffers.
Examples of sensitive information include but are not be limited to:


-  Keys
-  Initialization Vectors
-  Context Structures


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   If any such sensitive data is passed to Intel® Cryptography Primitives Library, it is the
   responsibility of your application to scrub this information from the
   memory buffers.

