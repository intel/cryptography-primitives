## SM4 GCM multi buffer implementation

### Implemented functional

Code implements GCM (Galois/Counter Mode, see [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf)) of operation over SM4 block sipher.
GHASH implementation is a port of Intel(R) IPSec code ([sources](https://github.com/intel/intel-ipsec-mb/blob/main/lib/avx512/gcm_avx512.asm)).
For details see [Vinodh Gopal et. al. Optimized Galois-Counter-Mode Implementation on Intel Architecture Processors. August, 2010](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/communications-ia-galois-counter-mode-paper.pdf)
and [Erdinc Ozturk et. al. Enabling High-Performance Galois-Counter-Mode on Intel Architecture Processors. October, 2012](https://www.intel.cn/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf).

Implementation supports up to 16 buffers of input data. Additional implementation details will be described below.

### Internal functions

1) GHASH implementation
    * block multiplication
    * hash key computation
    * updating ghash value with single block of data
    * updating ghash value with multiple blocks of data (up to 8 blocks, using delayed reduction)
2) SM4 CTR kernel
3) GCM parts
    * IV processing
    * AAD processing
    * encryption with authentication
    * decryption with authentication
    * tag computation

See [sources](../../sources/ippcp/crypto_mb/src/sm4/gcm/internal) and [header](sources/ippcp/crypto_mb/include/internal/sm4/sm4_gcm_mb.h).

### APIs

Implemented APIs

```c
EXTERN_C mbx_status16 mbx_sm4_gcm_init_mb16(const sm4_key* pa_key[SM4_LINES],
                                            const int8u* pa_iv[SM4_LINES],
                                            const int iv_len[SM4_LINES],
                                            SM4_GCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 mbx_sm4_gcm_update_iv_mb16(const int8u* pa_iv[SM4_LINES],
                                                 const int iv_len[SM4_LINES],
                                                 SM4_GCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 mbx_sm4_gcm_update_aad_mb16(const int8u* pa_aad[SM4_LINES],
                                                  const int aad_len[SM4_LINES],
                                                  SM4_GCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 mbx_sm4_gcm_encrypt_mb16(int8u* pa_out[SM4_LINES],
                                               const int8u* pa_in[SM4_LINES],
                                               const int in_len[SM4_LINES],
                                               SM4_GCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 mbx_sm4_gcm_decrypt_mb16(int8u* pa_out[SM4_LINES],
                                               const int8u* pa_in[SM4_LINES],
                                               const int in_len[SM4_LINES],
                                               SM4_GCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 mbx_sm4_gcm_get_tag_mb16(int8u* pa_out[SM4_LINES],
                                               const int tag_len[SM4_LINES],
                                               SM4_GCM_CTX_mb16* p_context);
```

Arguments:
* pa_key - array of 16 pointers to buffers with encryption/decryption keys
* pa_iv - array of 16 pointers to buffers with IV (initialization vector)
* iv_len - array of IV lengths
* p_context - pointer to the context to keep intermediate results between calls
* pa_aad - array of 16 pointers to buffers with AAD (additional authenticated data)
* aad_len - array of AAD lengths
* pa_out - array of 16 pointers to output buffers
* pa_in - array of 16 pointers to input buffers
* in_len - array of lengths of data in input buffers
* tag_len - array of lengths of tags

See [sources](../../sources/ippcp/crypto_mb/src/sm4/gcm/api) and [header](sources/ippcp/crypto_mb/include/crypto_mb/sm4_gcm.h).

### Additional implementation details

Multi call support
* implementation supports separated calls to provide an ability to process payload that divided to several parts (ex. plain text of 3kB size can be processed by 3 calls on 1 kB each, or 2 calls on 1 kB and 2 kB. Any other number of calls and any combinations of lengths is allowed if it is fit to call sequence restrictions)
)
* implementation uses a context to keep intermediate results between calls
* implementation uses a state machine to prevent wrong call sequence

Valid call sequence
1) mbx_sm4_gcm_init_mb16
2) mbx_sm4_gcm_update_iv_mb16 –  optional, can be called as many times as necessary
3) mbx_sm4_gcm_update_aad_mb16 –  optional, can be called as many times as necessary
4) mbx_sm4_gcm_encrypt_mb16/mbx_sm4_gcm_decrypt_mb16 –  optional, can be called as many times as necessary
5) mbx_sm4_gcm_get_tag_mb16

Call sequence restrictions
* mbx_sm4_gcm_get_tag_mb16 can be called after IV is fully processed. IV is fully processed if buffer with partial block (Block of less than 16 bytes size) was processed (by any of API 
mbx_sm4_gcm_init_mb16 or mbx_sm4_gcm_update_iv_mb16) or if mbx_sm4_gcm_update_aad_mb16 was called
* functions at steps 2-4 can be called as many times as needed to process payload while this functions processes buffers with full blocks (Blocks of 16 bytes size) or empty buffers and length of processed payload is not overflowed.
* if functions at steps 2-4 called to process a partial block, it can’t be called again.
* if mbx_sm4_gcm_update_aad_mb16 was called, mbx_sm4_gcm_update_iv_mb16 can’t be called.
* if mbx_sm4_gcm_encrypt_mb16 or mbx_sm4_gcm_decrypt_mb16 was called, mbx_sm4_gcm_update_aad_mb16 and mbx_sm4_gcm_update_iv_mb16 can’t be called.
* if mbx_sm4_gcm_encrypt_mb16 was called, mbx_sm4_gcm_decrypt_mb16 can’t be called.
* if mbx_sm4_gcm_decrypt_mb16 was called, mbx_sm4_gcm_encrypt_mb16 can’t be called.

[Full state machine.](/doc/images/crypto_mb/sm4_gsm_state_machine.jpg)

### Testing

Testing done:
* Cross-test with Tongsuo with random data
* KAT vectors
* CET tests
* Bad argument tests
