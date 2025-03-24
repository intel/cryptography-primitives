.. _function-naming-conventions:

Function Naming Conventions
===========================


Intel® Cryptography Primitives Library
functions have the same naming conventions for
all domains.


Function names in Intel® Cryptography Primitives Library have the following general
format:


:samp:`ipp{<data-domain>}{<name>}[\_{<descriptor>}]({<parameters>})`


.. note::


   The support functions in Intel® Cryptography Primitives Library like
   :samp:`ippcpGetCpuFeatures()` do not need an input data type. These functions
   have :samp:`ippcp` as a prefix without the data-domain field.


Data-domain
-----------


The :samp:`{data-domain}` element is a single character indicating type of input
data. Intel® Cryptography Primitives Library supports the following data-domain:


.. list-table::
   :widths: 1 3


   * - s
     - one-dimensional operations on signals, vectors, buffers




Parameters
----------


The :samp:`{parameters}` element specifies the function parameters (arguments).


The order of parameters is as follows:


-  All source operands. Constants follow vectors.
-  All destination operands. Constants follow vectors.
-  Other, operation-specific parameters.


A parameter name has the following conventions:


-  All parameters defined as pointers start with :samp:`{p}`, for example,
   :samp:`{pBuffer, pSrc}`; parameters defined as double pointers start with :samp:`{pp}`,
   for example, :samp:`{ppData}`. All parameters defined as values start with a
   lowercase letter, for example, :samp:`{length, bitSize, keyLen}`.
-  Each new part of a parameter name starts with an uppercase character,
   without underscore; for example, :samp:`{pSrc, bitSize, pResult}`.
-  Each parameter name specifies its functionality. Source parameters
   are named :samp:`{pSrc}` or :samp:`{src}`, in some cases followed by names or numbers,
   for example, :samp:`{pSrc2, srcLen}`. Output parameters are named :samp:`{pDst}` or :samp:`{dst}`
   followed by names or numbers, for example, :samp:`{pDst2, dstLen}`. For
   in-place operations, the input/output parameter contains the name
   :samp:`{pSrcDst}` or :samp:`{srcDst}`.

