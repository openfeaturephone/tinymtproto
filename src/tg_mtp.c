/* tg_mtp.c - MTProto 2.0 KDF and message encryption, ported from TDLib td/mtproto/KDF.cpp and
 * td/mtproto/Transport.cpp (Boost Software License 1.0). Comments name the TDLib function.
 *
 * Derived from TDLib, Copyright Aliaksei Levin, Arseny Smirnov 2014-2026, distributed under the
 * Boost Software License 1.0 (LICENSE_1_0.txt). Changes: C port for small freestanding targets;
 * see THIRD_PARTY.md. */
#include "tg_mtp.h"

/* KDF.cpp: tmp_KDF */
void tg_kdf_tmp(const uint8_t server_nonce[16], const uint8_t new_nonce[32], uint8_t key[32], uint8_t iv[32])
{
    uint8_t buf[64], sha_server_new[20];
    /* tmp_aes_key := SHA1(new_nonce + server_nonce) + substr(SHA1(server_nonce + new_nonce), 0, 12) */
    tg_memcpy(buf, new_nonce, 32);
    tg_memcpy(buf + 32, server_nonce, 16);
    tg_sha1(buf, 48, key);
    tg_memcpy(buf, server_nonce, 16);
    tg_memcpy(buf + 16, new_nonce, 32);
    tg_sha1(buf, 48, sha_server_new);
    tg_memcpy(key + 20, sha_server_new, 12);
    /* tmp_aes_iv := substr(SHA1(server_nonce + new_nonce), 12, 8) + SHA1(new_nonce + new_nonce) + substr(new_nonce, 0, 4) */
    tg_memcpy(iv, sha_server_new + 12, 8);
    tg_memcpy(buf, new_nonce, 32);
    tg_memcpy(buf + 32, new_nonce, 32);
    tg_sha1(buf, 64, iv + 8);
    tg_memcpy(iv + 28, new_nonce, 4);
}

/* KDF.cpp: KDF2 */
void tg_kdf2(const uint8_t auth_key[256], const uint8_t msg_key[16], int x, uint8_t key[32], uint8_t iv[32])
{
    uint8_t buf[52], a[32], b[32];
    /* sha256_a = SHA256(msg_key + substr(auth_key, x, 36)) */
    tg_memcpy(buf, msg_key, 16);
    tg_memcpy(buf + 16, auth_key + x, 36);
    tg_sha256(buf, 52, a);
    /* sha256_b = SHA256(substr(auth_key, 40+x, 36) + msg_key) */
    tg_memcpy(buf, auth_key + 40 + x, 36);
    tg_memcpy(buf + 36, msg_key, 16);
    tg_sha256(buf, 52, b);
    /* aes_key = a[0..8) + b[8..24) + a[24..32);  aes_iv = b[0..8) + a[8..24) + b[24..32) */
    tg_memcpy(key, a, 8);  tg_memcpy(key + 8, b + 8, 16); tg_memcpy(key + 24, a + 24, 8);
    tg_memcpy(iv, b, 8);   tg_memcpy(iv + 8, a + 8, 16);  tg_memcpy(iv + 24, b + 24, 8);
    tg_wipe(a, 32);
    tg_wipe(b, 32);
    tg_wipe(buf, sizeof buf);
}

/* Transport.cpp: calc_message_key2. msg_key = substr(SHA256(substr(auth_key, 88+x, 32) + plaintext), 8, 16) */
static void msg_key2(const uint8_t auth_key[256], int x, const uint8_t *plain, uint32_t len, uint8_t out[16])
{
    tg_sha256_t c;
    uint8_t large[32];
    tg_sha256_init(&c);
    tg_sha256_update(&c, auth_key + 88 + x, 32);
    tg_sha256_update(&c, plain, len);
    tg_sha256_final(&c, large);
    tg_memcpy(out, large + 8, 16);
}

/* Transport.cpp: do_calc_crypto_size2_basic (enc header 16 = salt + session_id; raw 24) */
uint32_t tg_mtp_packet_size(uint32_t body_len)
{
    static const uint16_t sizes[9] = { 64, 128, 192, 256, 384, 512, 768, 1024, 1280 };
    uint32_t data = 16 + body_len;                       /* msg_id, seq_no, length, body */
    uint32_t enc = (16 + data + 12 + 15) & ~15u;
    for (int i = 0; i < 9; i++)
        if (enc <= sizes[i]) return 24 + sizes[i];
    return 24 + (enc - 1280 + 447) / 448 * 448 + 1280;
}

/* Transport.cpp: write_crypto_impl (version 2) */
uint32_t tg_mtp_encrypt(const uint8_t auth_key[256], const uint8_t auth_key_id[8], int x, tg_rng_t *rng,
                        uint8_t *buf, uint32_t body_len)
{
    uint32_t total = tg_mtp_packet_size(body_len);
    uint8_t key[32], iv[32];
    tg_rng_bytes(rng, buf + TG_MTP_HDR + body_len, total - (TG_MTP_HDR + body_len));
    tg_memcpy(buf, auth_key_id, 8);
    msg_key2(auth_key, x, buf + 24, total - 24, buf + 8);
    tg_kdf2(auth_key, buf + 8, x, key, iv);
    tg_aes_ige_encrypt(key, iv, buf + 24, buf + 24, total - 24);
    tg_wipe(key, 32);
    tg_wipe(iv, 32);
    return total;
}

/* Transport.cpp: read_crypto_impl (version 2, check_mod4). Unlike TDLib, a decrypted part that is
 * not a multiple of 16 is rejected instead of trimmed. */
int tg_mtp_decrypt(const uint8_t auth_key[256], const uint8_t auth_key_id[8], int x,
                   uint8_t *buf, uint32_t len, uint32_t *body_len)
{
    uint8_t key[32], iv[32], real[16];
    if (len < TG_MTP_HDR + 12 || (len - 24) % 16)
        return -1;
    if (tg_be_cmp(buf, auth_key_id, 8))
        return -2;
    tg_kdf2(auth_key, buf + 8, x, key, iv);
    tg_aes_ige_decrypt(key, iv, buf + 24, buf + 24, len - 24);
    tg_wipe(key, 32);
    tg_wipe(iv, 32);
    msg_key2(auth_key, x, buf + 24, len - 24, real);
    int bad = 0;
    for (int i = 0; i < 16; i++) bad |= real[i] ^ buf[8 + i];
    if (bad)
        return -3;
    uint32_t data_len = tg_rd32(buf + 52), tail = len - 40;   /* tail: from msg_id to the end */
    if (data_len % 4 || tail - 16 < data_len)
        return -4;
    uint32_t pad = tail - 16 - data_len;
    if (pad < 12 || pad > 1024)
        return -5;
    *body_len = data_len;
    return 0;
}
