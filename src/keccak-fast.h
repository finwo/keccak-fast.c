#ifndef FINWO_KECCAK_FAST_H
#define FINWO_KECCAK_FAST_H

#include <stddef.h>
#include <stdint.h>

typedef int (*kf_hash_fn)(uint8_t *out, size_t outlen, const uint8_t *in,
                          size_t inlen);

extern kf_hash_fn kf_shake128;
extern kf_hash_fn kf_shake256;
extern kf_hash_fn kf_sha3_224;
extern kf_hash_fn kf_sha3_256;
extern kf_hash_fn kf_sha3_384;
extern kf_hash_fn kf_sha3_512;
extern kf_hash_fn kf_turboshake128;
extern kf_hash_fn kf_turboshake256;

int kf_shake128_batch(size_t count, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t outlen);
int kf_shake256_batch(size_t count, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t outlen);
int kf_sha3_224_batch(size_t count, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t outlen);
int kf_sha3_256_batch(size_t count, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t outlen);
int kf_sha3_384_batch(size_t count, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t outlen);
int kf_sha3_512_batch(size_t count, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t outlen);

const char *kf_backend_name(void);
const char *kf_batch_name(void);

#endif
