/* tg_crypto.h - crypto primitives for tinymtproto.
 *
 * Rules for every file in src/ (they come from the original target, position-independent apps on a
 * feature phone): no writable globals (every function works on a caller-owned context), byte-wise
 * access to caller buffers (any alignment is fine), no libc, no 64-bit division. The same files build
 * for the PC (tests/). */
#ifndef TG_CRYPTO_H
#define TG_CRYPTO_H

#include <stdint.h>

void tg_memcpy(void *d, const void *s, uint32_t n);
void tg_memset(void *d, int c, uint32_t n);
void tg_wipe(void *p, uint32_t n);                /* zero that the optimiser keeps */

/* ---- SHA-1 / SHA-256 ---- */
typedef struct { uint32_t h[5]; uint32_t len_lo, len_hi; uint8_t buf[64]; uint32_t used; } tg_sha1_t;
typedef struct { uint32_t h[8]; uint32_t len_lo, len_hi; uint8_t buf[64]; uint32_t used; } tg_sha256_t;
void tg_sha1_init(tg_sha1_t *c);
void tg_sha1_update(tg_sha1_t *c, const void *data, uint32_t len);
void tg_sha1_final(tg_sha1_t *c, uint8_t out[20]);
void tg_sha1(const void *data, uint32_t len, uint8_t out[20]);
void tg_sha256_init(tg_sha256_t *c);
void tg_sha256_update(tg_sha256_t *c, const void *data, uint32_t len);
void tg_sha256_final(tg_sha256_t *c, uint8_t out[32]);
void tg_sha256(const void *data, uint32_t len, uint8_t out[32]);

/* ---- AES-256 and IGE mode (MTProto) ---- */
typedef struct { uint32_t rk[60]; } tg_aes256_t;  /* expanded key, same schedule for both directions */
void tg_aes256_setkey(tg_aes256_t *c, const uint8_t key[32]);
void tg_aes256_encrypt(const tg_aes256_t *c, const uint8_t in[16], uint8_t out[16]);
void tg_aes256_decrypt(const tg_aes256_t *c, const uint8_t in[16], uint8_t out[16]);
/* len must be a multiple of 16; in == out is allowed. iv[0..15] = previous ciphertext block,
 * iv[16..31] = previous plaintext block (the MTProto / OpenSSL convention). iv is not updated. */
void tg_aes_ige_encrypt(const uint8_t key[32], const uint8_t iv[32], const uint8_t *in, uint8_t *out, uint32_t len);
void tg_aes_ige_decrypt(const uint8_t key[32], const uint8_t iv[32], const uint8_t *in, uint8_t *out, uint32_t len);

/* ---- bignum modular exponentiation (Montgomery, 4-bit windows, steppable) ----
 * Moduli up to 2048 bits, odd (RSA moduli and the DH prime are). Numbers cross the API as
 * big-endian byte strings, as in the TL wire format. */
#define TG_BN_LIMBS 64
typedef struct {
    uint32_t n[TG_BN_LIMBS];        /* modulus */
    uint32_t rr[TG_BN_LIMBS];       /* R^2 mod n */
    uint32_t tab[16][TG_BN_LIMBS];  /* base^i in Montgomery form */
    uint32_t acc[TG_BN_LIMBS];
    uint32_t t[TG_BN_LIMBS + 2];    /* scratch for the Montgomery product */
    uint32_t n0;                    /* -n^-1 mod 2^32 */
    uint32_t nl;                    /* limbs in use */
    uint32_t mod_len;               /* modulus length in bytes (output length) */
    uint8_t  exp[256];
    uint32_t exp_len;
    uint32_t nib;                   /* next exponent nibble (from the most significant) */
    uint32_t stage;                 /* 0 setup R^2, 1 table, 2 windows, 3 done */
    uint32_t prog;
} tg_modexp_t;
/* Returns 0 on success, -1 on a bad modulus (even, zero, too long) or exponent too long.
 * base must be < mod (it is reduced otherwise, slowly, by the R^2 path: keep it < mod). */
int tg_modexp_start(tg_modexp_t *c, const uint8_t *base, uint32_t base_len,
                    const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len);
/* Does about `budget` Montgomery products; returns 1 when finished, 0 if more steps are needed. */
int tg_modexp_step(tg_modexp_t *c, uint32_t budget);
void tg_modexp_result(const tg_modexp_t *c, uint8_t *out);   /* mod_len bytes, big-endian */

/* big-endian byte-string helpers (equal lengths) */
int tg_be_cmp(const uint8_t *a, const uint8_t *b, uint32_t len);
uint32_t tg_be_sub(uint8_t *r, const uint8_t *a, const uint8_t *b, uint32_t len);  /* returns borrow */

/* ---- PQ factorisation for req_pq (Pollard rho, no division instructions) ---- */
typedef struct {
    uint64_t n, x, y, c, q, ys;
    uint32_t iter, done;
    uint32_t p_out, q_out;          /* p < q */
} tg_pq_t;
void tg_pq_start(tg_pq_t *c, uint64_t pq);
int tg_pq_step(tg_pq_t *c, uint32_t budget);   /* 1 = done (p_out/q_out set; both 0 = failed) */

#endif
