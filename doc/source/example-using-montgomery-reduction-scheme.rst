.. _example-montgomery-reduction-scheme:




Example of Using Montgomery Reduction Scheme Functions
======================================================


.. container:: example
   :name: EX5-5


   .. rubric:: Montgomery Multiplication  
      :class: sectiontitle

   .. code-block:: cpp


      void MontMul_sample(void){</codeblock>
         int size;
       

         // define and initialize Montgomery Engine over Modulus N
         Ipp32u bnuN = 19;
         ippsMontGetSize(IppsBinaryMethod, 1, &amp;size);
         IppsMontState* pMont = (IppsMontState*)( new Ipp8u [size] );
         ippsMontInit(IppsBinaryMethod, 1, pMont);
         ippsMontSet(&amp;bnuN, 1, pMont);
       

         // define and init Big Number multiplicant A
         Ipp32u bnuA = 12;
         IppsBigNumState* bnA = New_BN(1, &amp;bnuA);
         // encode A into Montfomery form
         ippsMontForm(bnA, pMont, bnA);
       

         // define and init Big Number multiplicant A
         Ipp32u bnuB = 15;
         IppsBigNumState* bnB = New_BN(1, &amp;bnuB);
       

       

         // compute R = A*B mod N
         IppsBigNumState* bnR = New_BN(1);
         ippsMontMul(bnA, bnB, pMont, bnR);
       

         Type_BN("R = A*B mod N:\n", bnR);
         delete [] (Ipp8u*)pMont;
         delete [] (Ipp8u*)bnA;
         delete [] (Ipp8u*)bnB;
         delete [] (Ipp8u*)bnR;
      }

