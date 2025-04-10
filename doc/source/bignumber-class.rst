.. _bignumber-class:



BigNumber Class
===============


The section presents source code of the BigNumber class.

.. _declarations:

Declarations
------------


Contents of the header file (xsample_bignum.h) declaring the BigNumber
class are presented below:


.. code-block:: cpp


   #if !defined _BIGNUMBER_H_
   #define _BIGNUMBER_H_


   #include "ippcp.h"


   #include <iostream>
   #include <vector>
   #include <iterator>
   using namespace std;


   class BigNumber
   {
   public:
      BigNumber(Ipp32u value=0);
      BigNumber(Ipp32s value);
      BigNumber(const IppsBigNumState* pBN);
      BigNumber(const Ipp32u* pData, int length=1, IppsBigNumSGN sgn=IppsBigNumPOS);
      BigNumber(const BigNumber& bn);
      BigNumber(const char *s);
      virtual ~BigNumber();


      // set value
      void Set(const Ipp32u* pData, int length=1, IppsBigNumSGN sgn=IppsBigNumPOS);
      // conversion to IppsBigNumState
      friend IppsBigNumState* BN(const BigNumber& bn) {return bn.m_pBN;}
      operator IppsBigNumState* () const { return m_pBN; }


      // some useful constants
      static const BigNumber& Zero();
      static const BigNumber& One();
      static const BigNumber& Two();


      // arithmetic operators probably need
      BigNumber& operator = (const BigNumber& bn);
      BigNumber& operator += (const BigNumber& bn);
      BigNumber& operator -= (const BigNumber& bn);
      BigNumber& operator *= (Ipp32u n);
      BigNumber& operator *= (const BigNumber& bn);
      BigNumber& operator /= (const BigNumber& bn);
      BigNumber& operator %= (const BigNumber& bn);
      friend BigNumber operator + (const BigNumber& a, const BigNumber& b);
      friend BigNumber operator - (const BigNumber& a, const BigNumber& b);
      friend BigNumber operator * (const BigNumber& a, const BigNumber& b);
      friend BigNumber operator * (const BigNumber& a, Ipp32u);
      friend BigNumber operator % (const BigNumber& a, const BigNumber& b);
      friend BigNumber operator / (const BigNumber& a, const BigNumber& b);


      // modulo arithmetic
      BigNumber Modulo(const BigNumber& a) const;
      BigNumber ModAdd(const BigNumber& a, const BigNumber& b) const;
      BigNumber ModSub(const BigNumber& a, const BigNumber& b) const;
      BigNumber ModMul(const BigNumber& a, const BigNumber& b) const;
      BigNumber InverseAdd(const BigNumber& a) const;
      BigNumber InverseMul(const BigNumber& a) const;


      // comparisons
      friend bool operator < (const BigNumber& a, const BigNumber& b);
      friend bool operator > (const BigNumber& a, const BigNumber& b);
      friend bool operator == (const BigNumber& a, const BigNumber& b);
      friend bool operator != (const BigNumber& a, const BigNumber& b);
      friend bool operator <= (const BigNumber& a, const BigNumber& b) {return !(a>b);}
      friend bool operator >= (const BigNumber& a, const BigNumber& b) {return !(a<b);}


      // easy tests
      bool IsOdd() const;
      bool IsEven() const { return !IsOdd(); }


      // size of BigNumber
      int MSB() const;
      int LSB() const;
      int BitSize() const { return MSB()+1; }
      int DwordSize() const { return (BitSize()+31)>>5;}
      friend int Bit(const vector<Ipp32u>& v, int n);


      // conversion and output
      void num2hex( string& s ) const; // convert to hex string
      void num2vec( vector<Ipp32u>& v ) const; // convert to 32-bit word vector
      friend ostream& operator << (ostream& os, const BigNumber& a);


   protected:
      bool create(const Ipp32u* pData, int length, IppsBigNumSGN sgn=IppsBigNumPOS);
      int compare(const BigNumber& ) const;
      IppsBigNumState* m_pBN;
   };


   // convert bit size into 32-bit words
   #define BITSIZE_WORD(n) ((((n)+31)>>5))


   #endif // _BIGNUMBER_H_


Definitions
-----------


C++ definitions for the BigNumber class methods are given below. For the
declarations to be included, see the preceding
`Declarations <#declarations>`__ section.


.. code-block:: cpp


   #include "xsample_bignum.h"
   //////////////////////////////////////////////////////////////////////
   //
   // BigNumber
   //
   //////////////////////////////////////////////////////////////////////
   BigNumber::~BigNumber()
   {
      delete [] (Ipp8u*)m_pBN;
   }


   bool BigNumber::create(const Ipp32u* pData, int length, IppsBigNumSGN sgn)
   {
      int size;
      ippsBigNumGetSize(length, &size);
      m_pBN = (IppsBigNumState*)( new Ipp8u[size] );
      if(!m_pBN)
         return false;
      ippsBigNumInit(length, m_pBN);
      if(pData)
         ippsSet_BN(sgn, length, pData, m_pBN);
      return true;
   }


   // constructors
   //
   BigNumber::BigNumber(Ipp32u value)
   {
      create(&value, 1, IppsBigNumPOS);
   }


   BigNumber::BigNumber(Ipp32s value)
   {
      Ipp32s avalue = abs(value);
      create((Ipp32u*)&avalue, 1, (value<0)? IppsBigNumNEG : IppsBigNumPOS);
   }


   BigNumber::BigNumber(const IppsBigNumState* pBN)
   {
      IppsBigNumSGN bnSgn;
      int bnBitLen;
      Ipp32u* bnData;
      ippsRef_BN(&bnSgn, &bnBitLen, &bnData, pBN);


      create(bnData, BITSIZE_WORD(bnBitLen), bnSgn);
   }


   BigNumber::BigNumber(const Ipp32u* pData, int length, IppsBigNumSGN sgn)
   {
      create(pData, length, sgn);
   }


   static char HexDigitList[] = "0123456789ABCDEF";


   BigNumber::BigNumber(const char* s)
   {
      bool neg = '-' == s[0];
      if(neg) s++;
      bool hex = ('0'==s[0]) && (('x'==s[1]) || ('X'==s[1]));


      int dataLen;
      Ipp32u base;
      if(hex) {
         s += 2;
         base = 0x10;
         dataLen = (int)(strlen(s) + 7)/8;
      }
      else {
         base = 10;
         dataLen = (int)(strlen(s) + 9)/10;
      }


      create(0, dataLen);
      *(this) = Zero();
      while(*s) {
         char tmp[2] = {s[0],0};
         Ipp32u digit = (Ipp32u)strcspn(HexDigitList, tmp);
         *this = (*this) * base + BigNumber( digit );
         s++;
      }


      if(neg)
         (*this) = Zero()- (*this);
   }


   BigNumber::BigNumber(const BigNumber& bn)
   {
      IppsBigNumSGN bnSgn;
      int bnBitLen;
      Ipp32u* bnData;
      ippsRef_BN(&bnSgn, &bnBitLen, &bnData, bn);


      create(bnData, BITSIZE_WORD(bnBitLen), bnSgn);
   }


   // set value
   //
   void BigNumber::Set(const Ipp32u* pData, int length, IppsBigNumSGN sgn)
   {
      ippsSet_BN(sgn, length, pData, BN(*this));
   }


   // constants
   //
   const BigNumber& BigNumber::Zero()
   {
      static const BigNumber zero(0);
      return zero;
   }


   const BigNumber& BigNumber::One()
   {
      static const BigNumber one(1);
      return one;
   }


   const BigNumber& BigNumber::Two()
   {
      static const BigNumber two(2);
      return two;
   }


   // arithmetic operators
   //
   BigNumber& BigNumber::operator =(const BigNumber& bn)
   {
      if(this != &bn) {    // prevent self copy
         IppsBigNumSGN bnSgn;
         int bnBitLen;
         Ipp32u* bnData;
         ippsRef_BN(&bnSgn, &bnBitLen, &bnData, bn);


         delete (Ipp8u*)m_pBN;
         create(bnData, BITSIZE_WORD(bnBitLen), bnSgn);
      }
      return *this;
   }


   BigNumber& BigNumber::operator += (const BigNumber& bn)
   {
      int aBitLen;
      ippsRef_BN(NULL, &aBitLen, NULL, *this);
      int bBitLen;
      ippsRef_BN(NULL, &bBitLen, NULL, bn);
      int rBitLen = IPP_MAX(aBitLen, bBitLen) + 1;


      BigNumber result(0, BITSIZE_WORD(rBitLen));
      ippsAdd_BN(*this, bn, result);
      *this = result;
      return *this;
   }


   BigNumber& BigNumber::operator -= (const BigNumber& bn)
   {
      int aBitLen;
      ippsRef_BN(NULL, &aBitLen, NULL, *this);
      int bBitLen;
      ippsRef_BN(NULL, &bBitLen, NULL, bn);
      int rBitLen = IPP_MAX(aBitLen, bBitLen);


      BigNumber result(0, BITSIZE_WORD(rBitLen));
      ippsSub_BN(*this, bn, result);
      *this = result;
      return *this;
   }


   BigNumber& BigNumber::operator *= (const BigNumber& bn)
   {
      int aBitLen;
      ippsRef_BN(NULL, &aBitLen, NULL, *this);
      int bBitLen;
      ippsRef_BN(NULL, &bBitLen, NULL, bn);
      int rBitLen = aBitLen + bBitLen;


      BigNumber result(0, BITSIZE_WORD(rBitLen));
      ippsMul_BN(*this, bn, result);
      *this = result;
      return *this;
   }


   BigNumber& BigNumber::operator *= (Ipp32u n)
   {
      int aBitLen;
      ippsRef_BN(NULL, &aBitLen, NULL, *this);


      BigNumber result(0, BITSIZE_WORD(aBitLen+32));
      BigNumber bn(n);
      ippsMul_BN(*this, bn, result);
      *this = result;
      return *this;
   }


   BigNumber& BigNumber::operator %= (const BigNumber& bn)
   {
      BigNumber remainder(bn);
      ippsMod_BN(BN(*this), BN(bn), BN(remainder));
      *this = remainder;
      return *this;
   }


   BigNumber& BigNumber::operator /= (const BigNumber& bn)
   {
      BigNumber quotient(*this);
      BigNumber remainder(bn);
      ippsDiv_BN(BN(*this), BN(bn), BN(quotient), BN(remainder));
      *this = quotient;
      return *this;
   }


   BigNumber operator + (const BigNumber& a, const BigNumber& b )
   {
      BigNumber r(a);
      return r += b;
   }


   BigNumber operator - (const BigNumber& a, const BigNumber& b )
   {
      BigNumber r(a);
      return r -= b;
   }


   BigNumber operator * (const BigNumber& a, const BigNumber& b )
   {
      BigNumber r(a);
      return r *= b;
   }


   BigNumber operator * (const BigNumber& a, Ipp32u n)
   {
      BigNumber r(a);
      return r *= n;
   }


   BigNumber operator / (const BigNumber& a, const BigNumber& b )
   {
      BigNumber q(a);
      return q /= b;
   }


   BigNumber operator % (const BigNumber& a, const BigNumber& b )
   {
      BigNumber r(b);
      ippsMod_BN(BN(a), BN(b), BN(r));
      return r;
   }


   // modulo arithmetic
   //
   BigNumber BigNumber::Modulo(const BigNumber& a) const
   {
      return a % *this;
   }


   BigNumber BigNumber::InverseAdd(const BigNumber& a) const
   {
      BigNumber t = Modulo(a);
      if(t==BigNumber::Zero())
         return t;
      else
      return *this - t;
   }


   BigNumber BigNumber::InverseMul(const BigNumber& a) const
   {
      BigNumber r(*this);
      ippsModInv_BN(BN(a), BN(*this), BN(r));
      return r;
   }


   BigNumber BigNumber::ModAdd(const BigNumber& a, const BigNumber& b) const
   {
      BigNumber r = this->Modulo(a+b);
      return r;
   }


   BigNumber BigNumber::ModSub(const BigNumber& a, const BigNumber& b) const
   {
      BigNumber r = this->Modulo(a + this->InverseAdd(b));
      return r;
   }


   BigNumber BigNumber::ModMul(const BigNumber& a, const BigNumber& b) const
   {
      BigNumber r = this->Modulo(a*b);
      return r;
   }


   // comparison
   //
   int BigNumber::compare(const BigNumber &bn) const
   {
      Ipp32u result;
      BigNumber tmp = *this - bn;
      ippsCmpZero_BN(BN(tmp), &result);
      return (result==IS_ZERO)? 0 : (result==GREATER_THAN_ZERO)? 1 : -1;
   }


   bool operator <  (const BigNumber &a, const BigNumber &b) { return a.compare(b) < 0; }
   bool operator >  (const BigNumber &a, const BigNumber &b) { return a.compare(b) > 0; }
   bool operator == (const BigNumber &a, const BigNumber &b) { return 0 == a.compare(b);}
   bool operator != (const BigNumber &a, const BigNumber &b) { return 0 != a.compare(b);}


   // easy tests
   //
   bool BigNumber::IsOdd() const
   {
      Ipp32u* bnData;
      ippsRef_BN(NULL, NULL, &bnData, *this);
      return bnData[0]&1;
   }


   // size of BigNumber
   //
   int BigNumber::LSB() const
   {
      if( *this == BigNumber::Zero() )
         return 0;


      vector<Ipp32u> v;
      num2vec(v);


      int lsb = 0;
      vector<Ipp32u>::iterator i;
      for(i=v.begin(); i!=v.end(); i++) {
         Ipp32u x = *i;
         if(0==x)
            lsb += 32;
         else {
            while(0==(x&1)) {
               lsb++;
               x >>= 1;
            }
            break;
         }
      }
      return lsb;
   }


   int BigNumber::MSB() const
   {
      if( *this == BigNumber::Zero() )
         return 0;


      vector<Ipp32u> v;
      num2vec(v);


      int msb = (int)v.size()*32 -1;
      vector<Ipp32u>::reverse_iterator i;
      for(i=v.rbegin(); i!=v.rend(); i++) {
         Ipp32u x = *i;
         if(0==x)
            msb -=32;
         else {
            while(!(x&0x80000000)) {
               msb--;
               x <<= 1;
            }
            break;
         }
      }
      return msb;
   }


   int Bit(const vector<Ipp32u>& v, int n)
   {
      return 0 != ( v[n>>5] & (1<<(n&0x1F)) );
   }


   // conversions and output
   //
   void BigNumber::num2vec( vector<Ipp32u>& v ) const
   {
      int bnBitLen;
      Ipp32u* bnData;
      ippsRef_BN(NULL, &bnBitLen, &bnData, *this);


      int len = BITSIZE_WORD(bnBitLen);
      for(int n=0; n<len; n++)
         v.push_back( bnData[n] );
   }


   void BigNumber::num2hex( string& s ) const
   {
      IppsBigNumSGN bnSgn;
      int bnBitLen;
      Ipp32u* bnData;
      ippsRef_BN(&bnSgn, &bnBitLen, &bnData, *this);


      int len = BITSIZE_WORD(bnBitLen);


      s.append(1, (bnSgn==ippBigNumNEG)? '-' : ' ');
      s.append(1, '0');
      s.append(1, 'x');
      for(int n=len; n>0; n--) {
         Ipp32u x = bnData[n-1];
         for(int nd=8; nd>0; nd--) {
            char c = HexDigitList[(x>>(nd-1)*4)&0xF];
            s.append(1, c);
         }
      }
   }


   ostream& operator << ( ostream &os, const BigNumber& a)
   {
      string s;
      a.num2hex(s);
      os << s.c_str();
      return os;
   }
    


