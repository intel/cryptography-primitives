.. _example-of-using-aes-functions:

Example of Using AES Functions
==============================


.. container:: example
   :name: EX2-2


   .. rubric:: AES Encryption and Decryption
      :class: sectiontitle

   .. code-block:: cpp


          // use of the CTR mode
      int AES_sample(void)
      {
         // secret key
         Ipp8u key[] = "\x00\x01\x02\x03\x04\x05\x06\x07"
                       "\x08\x09\x10\x11\x12\x13\x14\x15";
         // define and setup AES cipher
         int ctxSize;
         ippsAESGetSize(&ctxSize);
         IppsAESSpec* pAES = (IppsAESSpec*)( new Ipp8u [ctxSize] );
         ippsAESInit(key, sizeof(key)-1, pAES, ctxSize);


         // message to be encrypted
         Ipp8u msg[] = "the quick brown fox jumps over the lazy dog";
         // and initial counter
         Ipp8u ctr0[] = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
                        "\x77\x66\x55\x44\x33\x22\x11\x00";


         // counter
         Ipp8u ctr[16];


         // init counter before encryption
         memcpy(ctr, ctr0, sizeof(ctr));
         // encrypted message
         Ipp8u ctext[sizeof(msg)];
         // encryption
         ippsAESEncryptCTR(msg, ctext, sizeof(msg), pAES, ctr, 64);


         // init counter before decryption
         memcpy(ctr, ctr0, sizeof(ctr));
         // decrypted message
         Ipp8u rtext[sizeof(ctext)];
         // decryption
         ippsAESDecryptCTR(ctext, rtext, sizeof(ctext), pAES, ctr, 64);


         // remove secret and release resource
         ippsAESInit(0, sizeof(key)-1, pAES, ctxSize);
         delete [] (Ipp8u*)pAES;


         int error = memcmp(rtext, msg, sizeof(msg));
         return 0==error;
      }

