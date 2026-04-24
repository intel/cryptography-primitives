.. _gfpxmethod:



GFpxMethod
==========


Returns a reference to the implementation of arithmetic operations over
GF(p\ :sup:`d`).


Syntax
------


const IppsGFpMethod\* ippsGFpxMethod_com(void);


const IppsGFpMethod\* ippsGFpxMethod_binom2(void);


const IppsGFpMethod\* ippsGFpxMethod_binom3(void);


const IppsGFpMethod\* ippsGFpxMethod_binom(void);


Include Files
-------------


``ippcp.h``


Description
-----------


Each of these functions returns a pointer to a structure containing an
implementation of arithmetic operations over GF(``p``\ :sup:`d`).


ippsGFpxMethod_com assumes an arbitrary value of the field polynomial
``g``\ (``x``); each of the rest of the functions returns a pointer to
the implementation of arithmetic operations over GF(``p``\ :sup:`d`)
tailored for a particular value of ``g``\ (``x``). See the table below
for the correspondence between method functions and values of the field
polynomial ``g``\ (``x``).


.. note::


   ippsGFpxMethod_binom2_epid2() and ippsGFpxMethod_binom3_epid2() are
   designed especially for the construction of finite field extensions
   for applications that use the Intel® Enhanced Privacy ID 2.0 scheme.

