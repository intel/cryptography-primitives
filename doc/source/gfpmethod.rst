.. _gfpmethod:




GFpMethod
=========


Returns a reference to an implementation of arithmetic operations over
GF(q).


Syntax
------


const IppsGFpMethod\* ippsGFpMethod_p192r1(void);


const IppsGFpMethod\* ippsGFpMethod_p224r1(void);


const IppsGFpMethod\* ippsGFpMethod_p256r1(void);


const IppsGFpMethod\* ippsGFpMethod_p384r1(void);


const IppsGFpMethod\* ippsGFpMethod_p521r1(void);


const IppsGFpMethod\* ippsGFpMethod_p256sm2(void);


const IppsGFpMethod\* ippsGFpMethod_pArb(void);


Include Files
-------------


``ippcp.h``


Description
-----------


Each of these functions returns a pointer to a structure containing an
implementation of arithmetic operations over GF(``q``).


ippsGFpMethod_pArb() assumes an arbitrary modulus ``q``; each of the
rest of the functions returns a pointer to the implementation of
arithmetic operations over GF(``q``) tailored for a particular ``q``.
See the table below for the correspondence between method functions and
values of the modulus ``q``.


.. list-table:: 
   :header-rows: 1

   * -  Function
     -  Value of modulus ``q``
   * -  ippsGFpMethod_p192r1()
     -  ``q`` = 2\ :sup:`192` - 2\ :sup:`64` - 1
   * -  ippsGFpMethod_p224r1()
     -  ``q`` = 2\ :sup:`224` - 2\ :sup:`96` - 1
   * -  ippsGFpMethod_p256r1()
     -  ``q`` = 2\ :sup:`256` - 2\ :sup:`224` + 2\ :sup:`192` + 2\ :sup:`96` - 1
   * -  ippsGFpMethod_p384r1()
     -  ``q`` = 2\ :sup:`384` - 2\ :sup:`128` - 2\ :sup:`96` + 2\ :sup:`32` - 1
   * -  ippsGFpMethod_p521r1()
     -  ``q`` = 2\ :sup:`521` - 1
   * -  ippsGFpMethod_p256sm2()
     -  ``q`` = 2\ :sup:`256` - 2\ :sup:`224` - 2\ :sup:`96` + 2\ :sup:`64` - 1
   * -  ippsGFpMethod_pArb()
     -  Arbitrary modulus ``q``



