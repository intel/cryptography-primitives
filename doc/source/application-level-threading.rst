.. _application-level-threading:

Application Level Threading
===========================

Intel® Cryptography Primitives Library API can be used in a multi-threaded application.
The library is thread-safe in the sense that you can call its functions from multiple threads.
However, the library does **not** provide any internal synchronization mechanisms for stateful
objects. It is the application's responsibility to ensure that each thread operates on its own
independent instance of a state, or that proper synchronization is applied when threads share
state objects.

.. warning::

   Every stateful algorithm (for example, XMSS, ML-KEM, ML-DSA, and others) maintains internal
   mutable state. If multiple threads share the same state object (such as a private key, public
   key, signature state or any other states) **without** proper synchronization, a **data race**
   may occur, leading to undefined behavior and potentially incorrect or insecure results.

Best Practices
--------------

When using Intel® Cryptography Primitives Library in a multi-threaded application, consider the
following best practices:

- **Allocate per-thread state objects.** Each thread must have its own instances of all mutable
  state objects (private keys, public keys, signature states, scratch buffers, etc.). Do not share
  these objects across threads.

- **Read-only data can be shared.** Immutable inputs such as message buffers, algorithm
  identifiers, and size constants can safely be shared across threads without synchronization.

- **Use thread sanitizers for validation.** Tools such as Clang's ThreadSanitizer (``-fsanitize=thread``)
  can detect data races at runtime during the development and testing phases and are strongly recommended for
  validating multi-threaded usage.
