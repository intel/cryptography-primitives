.. _function-context-structures:


Function Context Structures
===========================


Some Intel® Cryptography Primitives Library functions use special structures to store
function-specific (context) information. For example, the
``IppsRijndael128Spec`` structure stores a set of round keys, a set of round
inverse keys, and key management information for the Rijndael cipher
scheme with the block size equal to 128.


Two different kinds of context structures are used:


-  Specification structures, which are not modified during the
   function's operation. Their names include the ``Spec`` suffix.
-  State structures, which are modified during operation. Their names
   include the ``State`` suffix.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   It is your application that defines the life cycle of the context:
   initialization, updating, and destruction.


Each type of context is initialized with the specific initialization
function. For example, the ``ippsAESInit`` function initializes the
user-supplied memory as the ``IppsAESState`` context.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   Your application must exclusively pass the address of the original
   (initialized by the suitable ``Init`` function) context to an Intel® Cryptography Primitives Library
   function.


   Simple copying of the context (for example, using ``memcpy()``) and
   passing the address of this copy instead of the address of the
   original context to an Intel® Cryptography Primitives Library call may lead to misinterpretation
   inside the library function.

