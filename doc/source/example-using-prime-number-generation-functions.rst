.. _example-prime-number-gen:


Example of Using Prime Number Generation Functions
==================================================


.. container:: example


   .. rubric:: Check Primality
      :class: sectiontitle

   .. code-block:: cpp


      int PrimeGen_sample(void){PrimeGen   int error = 0;


         int ctxSize;
         // define 256-bit Prime Generator
         int maxBitSize = 256;
         ippsPrimeGetSize(256, &ctxSize);
         IppsPrimeState* pPrimeG = (IppsPrimeState*)( new Ipp8u [ctxSize] );
         ippsPrimeInit(256, pPrimeG);


         // define Pseudo Random Generator (default settings)
         ippsPRNGGetSize(&ctxSize);
         IppsPRNGState* pRand = (IppsPRNGState*)(new Ipp8u [ctxSize] );
         ippsPRNGInit(160, pRand);


         do {
            Ipp32u result;

            // Important!
            // Due to security reasons hardware-based PRNG implementation is used in this sample.
            // A CPU has to support RDRAND instruction.

            // test primality of the value (known in advance)
            BigNumber P1("0xDB7C2ABF62E35E668076BEAD208B");
            ippsPrimeTest_BN(P1, 50, &result, pPrimeG, ippsPRNGenRDRAND, pRand);
            error = IPP_IS_PRIME!=result;
            if(error) {
               cout <<"Primality of the known prime isn't confirmed\n";
               break;
            }
            else cout <<"Primality of the known prime is confirmed\n";


            // generate 256-bit prime
            BigNumber P(0, 256/8);
            while( ippStsNoErr != ippsPrimeGen_BN(P, 256, 50, pPrimeG, ippsPRNGenRDRAND, pRand) ) ;
            // and test it
            ippsPrimeTest_BN(P, 50, &result, pPrimeG, ippsPRNGenRDRAND, pRand);
            error = IPP_IS_PRIME!=result;
            if(error) {
               cout <<"Primality of the generated number isn't confirmed\n";
               break;
            }
            else cout <<"Primality of the generated number  is confirmed\n";
         } while(0);


         delete [] (Ipp8u*)pRand;
         delete [] (Ipp8u*)pPrimeG;


         return 0==error;
      }

