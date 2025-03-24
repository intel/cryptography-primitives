.. _usage-example:




Usage Example
=============


.. code-block:: cpp


   ////////////////////////// Usage example for AES-SIV primitives //////////////////////
      // key:
      Ipp8u key[] =
         "\x7f\x7e\x7d\x7c\x7b\x7a\x79\x78\x77\x76\x75\x74\x73\x72\x71\x70"
         "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f";
      // ADs:
      Ipp8u ad1[] =
         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
         "\xde\xad\xda\xda\xde\xad\xda\xda\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
         "\x77\x66\x55\x44\x33\x22\x11\x00";
      Ipp8u ad2[] =
         "\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0";
      Ipp8u nonce[] =
         "\x09\xf9\x11\x02\x9d\x74\xe3\x5b\xd8\x41\x56\xc5\x63\x56\x88\xc0";


      // PT
      Ipp8u pt[] =
         "\x74\x68\x69\x73\x20\x69\x73\x20\x73\x6f\x6d\x65\x20\x70\x6c\x61"
         "\x69\x6e\x74\x65\x78\x74\x20\x74\x6f\x20\x65\x6e\x63\x72\x79\x70"
         "\x74\x20\x75\x73\x69\x6e\x67\x20\x53\x49\x56\x2d\x41\x45\x53";
      Ipp8u rt[sizeof(pt)];
      int authRes = 0xaa;


      Ipp8u auth_ct[16+sizeof(pt)-1];


      Ipp8u* adSlist[] = {ad1,
                          ad2,
                          nonce,
                          pt};
      int    adLlist[] = {(int)(sizeof(ad1)-1),
                          (int)(sizeof(ad2)-1),
                          (int)(sizeof(nonce)-1),
                          sizeof(pt)-1};
      Ipp8u v[16];


      // compute ISV
      ippsAES_S2V_CMAC(key, 16, (const Ipp8u**)adSlist, adLlist, sizeof(adSlist)/sizeof(void*), v);


      // encode
      ippsAES_SIVEncrypt(pt, auth_ct+16, sizeof(pt)-1, auth_ct,
     key, key+16, 16,
                         (const Ipp8u**)adSlist, adLlist, sizeof(adSlist)/sizeof(void*)-1);


      // decode
      ippsAES_SIVDecrypt(auth_ct+16, rt, sizeof(pt)-1, &authRes,
     key, key+16, 16,
                         (const Ipp8u**)adSlist, adLlist, sizeof(adSlist)/sizeof(void*)-1,
                         auth_ct);




      if((1==authRes) && (0==memcmp(pt, rt, sizeof(pt)-1)))
         printf("authenticated decryption passed\n");
      else
         printf("authenticated decryption failed\n");
   //////////////////////////////////////////////////////////////////////

