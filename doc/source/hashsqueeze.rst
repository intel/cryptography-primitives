.. _hashsqueeze:


HashSqueeze
===========

Squeezes an arbitrary number of hash bytes out of the hash state.

Syntax
------

IppStatus ippsHashSqueeze_rmf(Ipp8u \*pMD, const int digestLen,
IppsHashState_rmf \*pState)

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -     pMD
     -  Pointer to the buffer containing the output digest.
   * -     digestLen
     -  Length of the hash to be squeezed.
   * -     pState
     -  Pointer to the ``IppsHashState_rmf`` context.

Description
-----------

The function squeezes an arbitrary number of hash bytes out of the ``IppsHashState_rmf``
state and can be called repeatedly. It is used only with methods that allow output
to be arbitrarily long, e.g. ``SHAKE128``, ``SHAKE256``.
The function is used together with other streaming hash functions with *reduced memory footprint*
and has the following restrictions in terms of the call order for a specific ``IppsHashState_rmf`` state:

* ``ippsHashInit_rmf()`` can be called at any time.
* ``ippsHashUpdate_rmf()`` can be called at any time, but not after ``ippsHashSqueeze_rmf()``.
* ``ippsHashSqueeze_rmf()`` can be called at any time.
* ``ippsHashFinal_rmf()`` can be called at any time, but not after ``ippsHashSqueeze_rmf()``.
* ``ippsHashGetTag_rmf()`` can be called at any time, but not after ``ippsHashSqueeze_rmf()``.

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
     -     Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -     Indicates an error condition if the context parameter does not match the
           operation or if the call sequence of the processing API is not correct
           (see more details in the "Description" section).
   * -     ippStsOutOfRangeErr
     -     Indicates an error condition if ``digestLen`` is less than zero.
   * -     ippStsNotSupportedModeErr
     -     Indicates an error condition if the provided hash algorithm identifier is not supported.
