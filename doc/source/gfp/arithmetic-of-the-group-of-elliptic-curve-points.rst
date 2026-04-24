.. _arithmetic-of-the-group-of-elliptic-curve-points:


Arithmetic of the Group of Elliptic Curve Points
================================================


This section describes the Intel® Cryptography Primitives Library functions that implement arithmetic
operations with points of elliptic curves
:term:`EC <[EC]>`. The
elliptic curve is defined by the following equation:


``y``\ :sup:`2` = ``x``\ :sup:`3` + ``A`` ⋅ ``x`` + ``B``


where

*  ``A`` and ``B`` are the parameters of the curve
*  ``x`` and ``y`` are the coordinates of a point on the curve


This document considers elliptic curves constructed over the finite
field GF(``p``) (prime or its extension), therefore the arithmetic of
elliptic curves is based on the arithmetic of the underlying finite
field. In the equation above, ``A, B, x,`` and ``y`` belong to the
underlying field GF(``p``).

.. toctree::
   :maxdepth: 1


   gfpecgetsize
   gfpecinit
   gfpecset
   gfpecsetsubgroup
   gfpecinitstd
   gfpecbindgxytable
   gfpecget
   gfpecgetsubgroup
   gfpecscratchbuffersize
   gfpecverify
   gfpecpointgetsize
   gfpecpointinit
   gfpecsetpointatinfinity
   gfpecsetpoint-gfpecsetpointregular
   gfpecsetpointoctstring
   gfpecsetpointrandom
   gfpecmakepoint
   gfpecsetpointhash-gfpecsetpointhashbackcompatible
   gfpecgetpoint-gfpecgetpointregular
   gfpecgetpointoctstring
   gfpectstpoint
   gfpectstpointinsubgroup
   gfpeccpypoint
   gfpeccmppoint
   gfpecnegpoint
   gfpecaddpoint
   gfpecmulpoint
   gfpecprivatekey-gfpecpublickey-gfpectstkeypair
   gfpecpublickey
   gfpectstkeypair
   gfpecpsharedsecretdh-gfpecpsharedsecretdhc
   gfpecsharedsecretdhc
   gfpecpsigndsa-gfpecpsignnr-gfpecpsignsm2
   gfpecpverifydsa-gfpecpverifynr-gfpecpverifysm2
   gfpecsignnr
   gfpecverifynr
   gfpecsignsm2
   gfpecverifysm2