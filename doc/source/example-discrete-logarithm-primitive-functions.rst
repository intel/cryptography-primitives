.. _example-discrete-logarithm-functions:


Example of Using Discrete-logarithm Based Primitive Functions
=============================================================


.. container:: example
   :name: EX5-9


   .. rubric:: Use of DLPSignDSA and DLPVerifyDSA
      :class: sectiontitle

   .. code-block:: cpp


      //
            // known domain parameters
            //
            static const int M = 512; // DSA system bitsize
            static const int L = 160; // DSA order  bitsize


            static
            BigNumber P("0x8DF2A494492276AA3D25759BB06869CBEAC0D83AFB8D0CF7" \
                        "CBB8324F0D7882E5D0762FC5B7210EAFC2E9ADAC32AB7AAC" \
                        "49693DFBF83724C2EC0736EE31C80291");
             

            static
            BigNumber Q("0xC773218C737EC8EE993B4F2DED30F48EDACE915F");
             

            static
            BigNumber G("0x626D027839EA0A13413163A55B4CB500299D5522956CEFCB" \
                        "3BFF10F399CE2C2E71CB9DE5FA24BABF58E5B79521925C9C" \
                        "C42E9F6F464B088CC572AF53E6D78802");
             

            //
            // known DSA regular key pair
            //
            static
            BigNumber X("0x2070B3223DBA372FDE1C0FFC7B2E3B498B260614");
             

             

            static
            BigNumber Y("0x19131871D75B1612A819F29D78D1B0D7346F7AA77BB62A85" \
                        "9BFD6C5675DA9D212D3A36EF1672EF660B8C7C255CC0EC74" \
                        "858FBA33F44C06699630A76B030EE333");
             

             

            int DSAsign_verify_sample(void)
            {
               // DLP context
               IppsDLPState *DLPState = newDLP(M, L);
             

               // set up DLP crypto system
               ippsDLPSet(P, Q, G, DLPState);
             

              // message
               Ipp8u message[] = "abc";
             

               // compute message digest to be signed
               Ipp8u md[SHA1_DIGEST_LENGTH/8];
               ippsHashMessage_rmf(message, sizeof(message)-1, md, ippsHashMethod_SHA1());
               BigNumber digest(0, BITS_2_WORDS(SHA1_DIGEST_LENGTH));
               ippsSetOctString_BN(md, SHA1_DIGEST_LENGTH/8, digest);
             

               // generate ephemeral key pair (ephX,ephY)
               BigNumber ephX(0, BITS_2_WORDS(L));
               BigNumber ephY(0, BITS_2_WORDS(M));
             

             

               // Important!
               // Due to security reasons hardware-based PRNG implementation is initialized here.
               // A CPU has to support RDRAND instruction.
               IppsPRNGState* pRand = newPRNG();
               ippsDLPGenKeyPair(ephX, ephY, DLPState, ippsPRNGenRDRAND, pRand);
               deletePRNG(pRand);
               //
               // generate signature
               //
               BigNumber signR(0, BITS_2_WORDS(L));      // R and S signature's component
               BigNumber signS(0, BITS_2_WORDS(L));
               ippsDLPSetKeyPair(ephX, ephY, DLPState);  // set up ephemeral keys
               ippsDLPSignDSA(digest, X,                 // sign digest
                              signR, signS,
                              DLPState);
             

             

               //
               // verify signature
               //
               ippsDLPSetKeyPair(0, Y, DLPState);        // set up regular public key
               IppDLResult result;
               ippsDLPVerifyDSA(digest, signR,signS,     // verify
                                &result, DLPState);
             

               // remove actual keys from context and release resource
               ippsDLPInit(M, L, DLPState);
               deleteDLP(DLPState);
               return result==ippDLValid;
            }
             


