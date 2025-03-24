.. _example-of-using-tdes-functions:



Example of Using TDES Functions
===============================


.. container:: example
   :name: EX2-1


   .. rubric:: TDES Encryption and Decryption 
      :class: sectiontitle

   .. code-block:: cpp


      // Use of the ECB mode
      void TDES_sample(void){
            // size of the TDES algorithm block is equal to 8
            const int tdesBlkSize = 8;
            

            // get size of the context needed for the encryption/decryption operation
            int ctxSize;
            ippsDESGetSize(&ctxSize);
            // and allocate one
            IppsDESSpec* pCtx1 = (IppsDESSpec*)( new Ipp8u [ctxSize] );
            IppsDESSpec* pCtx2 = (IppsDESSpec*)( new Ipp8u [ctxSize] );
            IppsDESSpec* pCtx3 = (IppsDESSpec*)( new Ipp8u [ctxSize] );
            

            // define the key
            Ipp8u key1[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
            Ipp8u key2[] = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18};
            Ipp8u key3[] = {0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28};
            Ipp8u keyX[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
            

            // and prepare the context for the TDES usage
            ippsDESInit(key1, pCtx1);
            ippsDESInit(key2, pCtx2);
            ippsDESInit(key3, pCtx3);
            

            // define the message to be encrypted
            Ipp8u ptext[] = {"the quick brown fox jumps over the lazy dog"};
            // allocate enough memory for the ciphertext
            // note that
            // the size of ciphertext is always a multiple of the cipher block size
            Ipp8u ctext[(sizeof(ptext)+desBlkSize-1) &~(desBlkSize-1)];
            // encrypt (ECB mode) ptext message
            // pay attention to the 'length' parameter
            // it defines the number of bytes to be encrypted
            ippsTDESEncryptECB(ptext, ctext, sizeof(ctext), pCtx1, pCtx2, pCtx3, IppsCPPaddingNONE);
            

            // allocate memory for the decrypted message
            Ipp8u rtext[sizeof(ctext)];
            // decrypt (ECB mode) ctext message
            // pay attention to the 'length' parameter
            // it defines the number of bytes to be decrypted
            ippsTDESDecryptECB(ctext, rtext, sizeof(ctext), pCtx1, pCtx2, pCtx3, IppsCPPaddingNONE);
            

            // remove actual secret from contexts
            ippsDESInit(keyX, pCtx1);
            ippsDESInit(keyX, pCtx2);
            ippsDESInit(keyX, pCtx3);
            // release resources
            delete (Ipp8u*)pCtx1;
            delete (Ipp8u*)pCtx2;
            delete (Ipp8u*)pCtx3;
      }

