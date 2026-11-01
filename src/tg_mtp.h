/* tg_mtp.h - MTProto 2.0 key derivation and message encryption.
 * Ported from TDLib (Boost-1.0): td/mtproto/KDF.cpp (tmp_KDF, KDF2) and td/mtproto/Transport.cpp
 * (calc_message_key2, write_crypto_impl, read_crypto_impl, calc_crypto_size2 basic padding).
 * MTProto 1.0 (KDF v1) is not ported: servers speak 2.0.
 *
 * Derived from TDLib, Copyright Aliaksei Levin, Arseny Smirnov 2014-2026, distributed under the
 * Boost Software License 1.0 (LICENSE_1_0.txt). Changes: C port for small freestanding targets;
 * see THIRD_PARTY.md. */
#ifndef TG_MTP_H
#define TG_MTP_H

#include "tg_proto.h"

#define TG_X_CLIENT 0   /* client -> server */
#define TG_X_SERVER 8   /* server -> client */

/* tmp_aes_key / tmp_aes_iv for server_DH_params_ok and set_client_DH_params */
void tg_kdf_tmp(const uint8_t server_nonce[16], const uint8_t new_nonce[32], uint8_t key[32], uint8_t iv[32]);
/* MTProto 2.0: aes key/iv from auth_key, msg_key and the direction x */
void tg_kdf2(const uint8_t auth_key[256], const uint8_t msg_key[16], int x, uint8_t key[32], uint8_t iv[32]);

/* Packet: auth_key_id(8) msg_key(16) | salt(8) session_id(8) msg_id(8) seq_no(4) len(4) body pad.
 * TG_MTP_HDR = offset of the body. */
#define TG_MTP_HDR 56
/* Bytes needed for a body of body_len (TDLib's basic size buckets, padding 12..1024). */
uint32_t tg_mtp_packet_size(uint32_t body_len);
/* Encrypt in place. buf[24..56) (salt, session_id, msg_id, seq_no, len) and the body at
 * buf[56..56+body_len) are filled by the caller; buf must hold tg_mtp_packet_size(body_len).
 * Writes auth_key_id and msg_key, pads with rng bytes. Returns the packet length. */
uint32_t tg_mtp_encrypt(const uint8_t auth_key[256], const uint8_t auth_key_id[8], int x, tg_rng_t *rng,
                        uint8_t *buf, uint32_t body_len);
/* Decrypt in place and check auth_key_id, msg_key, length and padding (12..1024).
 * On success returns 0 and sets *body_len; the body is at buf + TG_MTP_HDR.
 * Errors: -1 too short / not a multiple of 16, -2 auth_key_id, -3 msg_key, -4 length, -5 padding. */
int tg_mtp_decrypt(const uint8_t auth_key[256], const uint8_t auth_key_id[8], int x,
                   uint8_t *buf, uint32_t len, uint32_t *body_len);

#endif
