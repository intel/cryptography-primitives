.. _example-of-using-rsa-algorithm-functions:

Example of Using RSA Primitive Functions
========================================


The following example illustrates the use of RSA primitives. The example
uses the BigNumber class and functions creating some cryptographic
contexts, whose source code can be found in :ref:`Appendix A <appendix-a-support-functions-and-classes>`.



.. container:: example
   :name: EX5-8


   .. rubric:: Use of RSA Primitives 
      :class: sectiontitle

   .. code-block:: cpp


      // P prime factor
      BigNumber    P("0xEECFAE81B1B9B3C908810B10A1B5600199EB9F44AEF4FDA493B81A9E3D84F632"
                       "124EF0236E5D1E3B7E28FAE7AA040A2D5B252176459D1F397541BA2A58FB6599");
      // Q prime factor
      BigNumber    Q("0xC97FB1F027F453F6341233EAAAD1D9353F6C42D08866B1D05A0F2035028B9D86"
                       "9840B41666B42E92EA0DA3B43204B5CFCE3352524D0416A5A441E700AF461503");
      // P's CRT exponent
      BigNumber   dP("0x54494CA63EBA0337E4E24023FCD69A5AEB07DDDC0183A4D0AC9B54B051F2B13E"
                       "D9490975EAB77414FF59C1F7692E9A2E202B38FC910A474174ADC93C1F67C981");
      // Q's CRT exponent
      BigNumber   dQ("0x471E0290FF0AF0750351B7F878864CA961ADBD3A8A7E991C5C0556A94C3146A7"
                       "F9803F8F6F8AE342E931FD8AE47A220D1B99A495849807FE39F9245A9836DA3D");
      // CRT coefficient
      BigNumber invQ("0xB06C4FDABB6301198D265BDBAE9423B380F271F73453885093077FCD39E2119F"
                       "C98632154F5883B167A967BF402B4E9E2E0F9656E698EA3666EDFB25798039F7");
      // rsa modulus N = P*Q
      BigNumber    N("0xBBF82F090682CE9C2338AC2B9DA871F7368D07EED41043A440D6B6F07454F51F"
                       "B8DFBAAF035C02AB61EA48CEEB6FCD4876ED520D60E1EC4619719D8A5B8B807F"
                       "AFB8E0A3DFC737723EE6B4B7D93A2584EE6A649D060953748834B2454598394E"
                       "E0AAB12D7B61A51F527A9A41F6C1687FE2537298CA2A8F5946F8E5FD091DBDCB");
      // private exponent
      BigNumber    D("0xA5DAFC5341FAF289C4B988DB30C1CDF83F31251E0668B42784813801579641B2"
                       "9410B3C7998D6BC465745E5C392669D6870DA2C082A939E37FDCB82EC93EDAC9"
                       "7FF3AD5950ACCFBC111C76F1A9529444E56AAF68C56C092CD38DC3BEF5D20A93"
                       "9926ED4F74A13EDDFBE1A1CECC4894AF9428C2B7B8883FE4463A4BC85B1CB3C1");
      // public exponent
      BigNumber    E("0x11");


      int RSA_sample(void)
      {
         int keyCtxSize;


         // (bit) size of key components
         int bitsN = N.BitSize();
         int bitsE = E.BitSize();
         int bitsP = P.BitSize();
         int bitsQ = Q.BitSize();


         // define and setup public key
         ippsRSA_GetSizePublicKey(bitsN, bitsE, &keyCtxSize);
         IppsRSAPublicKeyState* pPub = (IppsRSAPublicKeyState*)( new Ipp8u [keyCtxSize] );
         ippsRSA_InitPublicKey(bitsN, bitsE, pPub, keyCtxSize);
         ippsRSA_SetPublicKey(N, E, pPub);


         // define and setup (type2) private key
         ippsRSA_GetSizePrivateKeyType2(bitsP, bitsQ, &keyCtxSize);
         IppsRSAPrivateKeyState* pPrv = (IppsRSAPrivateKeyState*)( new Ipp8u [keyCtxSize] );
         ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, pPrv, keyCtxSize);
         ippsRSA_SetPrivateKeyType2(P, Q, dP, dQ, invQ, pPrv);


         // allocate scratch buffer
         int buffSizePublic;
         ippsRSA_GetBufferSizePublicKey(&buffSizePublic, pPub);
         int buffSizePrivate;
         ippsRSA_GetBufferSizePrivateKey(&buffSizePrivate, pPrv);
         int buffSize = max(buffSizePublic, buffSizePrivate);
         Ipp8u* scratchBuffer = NULL;
         scratchBuffer = new Ipp8u [buffSize];


         // error flag
         int error = 0;


         do {
            //
            // validate keys
            //


            // Important!
            // Due to security reasons hardware-based PRNG implementation is initialized here.
            // A CPU has to support RDRAND instruction.
            IppsPRNGState* pRand = newPRNG();
            // prime generator
            IppsPrimeState* pPrimeG = newPrimeGen(P.BitSize());


            int validateRes = IPP_IS_INVALID;
            ippsRSA_ValidateKeys(&validateRes,
                                 pPub, pPrv, NULL, scratchBuffer,
                                 10, pPrimeG, ippsPRNGenRDRAND, pRand);


            // delete geterators
            deletePrimeGen(pPrimeG);
            deletePRNG(pRand);


            if(IPP_IS_VALID!=validateRes) {
               cout <<"validation fail" << endl;
               error = 1;
               break;
            }


            // known plain- and ciper-texts
            BigNumber kat_PT("0x00EB7A19ACE9E3006350E329504B45E2CA82310B26DCD87D5C68F1EEA8F55267"
                               "C31B2E8BB4251F84D7E0B2C04626F5AFF93EDCFB25C9C2B3FF8AE10E839A2DDB"
                               "4CDCFE4FF47728B4A1B7C1362BAAD29AB48D2869D5024121435811591BE392F9"
                               "82FB3E87D095AEB40448DB972F3AC14F7BC275195281CE32D2F1B76D4D353E2D");
            BigNumber kat_CT("0x1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF7"
                               "63722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB"
                               "6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48"
                               "DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955");


            //
            // encrypt  message
            //
            BigNumber ct(0, N.DwordSize());
            ippsRSA_Encrypt(kat_PT, ct, pPub, scratchBuffer);
            if(ct!=kat_CT) {
               cout <<"encryption fail" << endl;
               error = 1;
               break;
            }


            //
            // decrypt message
            //
            BigNumber rt(0, N.DwordSize());
            ippsRSA_Decrypt(kat_CT, rt, pPrv, scratchBuffer);
            if(rt!=kat_PT) {
               cout <<"decryption fail" << endl;
               error = 1;
               break;
            }
         } while(0);


         delete [] scratchBuffer;


         delete [] (Ipp8u*) pPub;


         // remove sensitive data before release
         ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, pPrv, keyCtxSize);
         delete [] (Ipp8u*) pPrv;


         return error==0;
      }

