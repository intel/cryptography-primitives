.. _pseudorandom-number-generation-functions:



Pseudorandom Number Generation Functions
========================================


Many cryptographic systems rely on pseudorandom number generation
functions in their design that make the unpredictable nature inherited
from a pseudorandom number generator the security foundation to ensure
safe communication over open channels and protection against potential
adversaries.


This section describes functions that make the pseudorandom bit sequence
generator implemented by a US FIPS-approved method and based on a SHA-1
one-way hash function specified by :term:`FIPS PUB 186-2 <[FIPS PUB 186-2]>`\ *,
appendix 3*.


The application code for generating a sequence of pseudorandom bits
should perform the following sequence of operations:


#. Call the function
   :ref:`PRNGGetSize <prnggetsize>`
   to get the size required to configure the IppsPRNGState context.
#. Ensure that the required memory space is properly allocated. With the
   allocated memory, call the
   :ref:`PRNGInit <prnginit>`
   function to set up the default value of the parameters for
   pseudorandom generation process.
#. If the default values of the parameters are not satisfied, call the
   function PRNGSetSeed and/or
   :ref:`PRNGSetAugment <prngsetaugment>`
   and/or
   :ref:`PRNGSetModulus <prngsetmodulus>`
   and/or
   :ref:`PRNGSetH0 <prngseth0>`
   to reset any of the control pseudorandom generator parameters.
#. Keep calling the function
   :ref:`PRNGen <prngen>`
   or
   :ref:`PRNGen_BN <prngen_bn>`
   to generate pseudo random value of the desired format.
#. Clean up secret data stored in the context.
#. Free the memory allocated for the IppsPRNGState context by calling
   the operating system memory free service function.


.. rubric:: Related Information

:ref:`data-security-considerations`


.. toctree::
   :maxdepth: 1


   user-s-implementation-of-a-pseudorandom-number
   prnggetsize
   prnginit
   prngsetseed
   prnggetseed
   prngsetaugment
   prngsetmodulus
   prngseth0
   prngen
   prngenrdrand
   trngenrdseed
   prngen_bn
   prngenrdrand_bn
   trngenrdseed_bn
