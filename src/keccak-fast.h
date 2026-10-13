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
int kf_turboshake128_batch(size_t count, const uint8_t *in, size_t inlen,
                           uint8_t *out, size_t outlen);
int kf_turboshake256_batch(size_t count, const uint8_t *in, size_t inlen,
                           uint8_t *out, size_t outlen);

/* x_r = H(x_r || tail_r || ctr), ctr one byte from ctr0, +1 per iteration */
int kf_shake128_chain(size_t count, uint8_t *x, size_t outlen,
                      const uint8_t *tail, size_t tail_len, size_t ctr_len,
                      uint8_t ctr0, uint32_t iters);
int kf_shake256_chain(size_t count, uint8_t *x, size_t outlen,
                      const uint8_t *tail, size_t tail_len, size_t ctr_len,
                      uint8_t ctr0, uint32_t iters);
int kf_sha3_224_chain(size_t count, uint8_t *x, size_t outlen,
                      const uint8_t *tail, size_t tail_len, size_t ctr_len,
                      uint8_t ctr0, uint32_t iters);
int kf_sha3_256_chain(size_t count, uint8_t *x, size_t outlen,
                      const uint8_t *tail, size_t tail_len, size_t ctr_len,
                      uint8_t ctr0, uint32_t iters);
int kf_sha3_384_chain(size_t count, uint8_t *x, size_t outlen,
                      const uint8_t *tail, size_t tail_len, size_t ctr_len,
                      uint8_t ctr0, uint32_t iters);
int kf_sha3_512_chain(size_t count, uint8_t *x, size_t outlen,
                      const uint8_t *tail, size_t tail_len, size_t ctr_len,
                      uint8_t ctr0, uint32_t iters);
int kf_turboshake128_chain(size_t count, uint8_t *x, size_t outlen,
                           const uint8_t *tail, size_t tail_len,
                           size_t ctr_len, uint8_t ctr0, uint32_t iters);
int kf_turboshake256_chain(size_t count, uint8_t *x, size_t outlen,
                           const uint8_t *tail, size_t tail_len,
                           size_t ctr_len, uint8_t ctr0, uint32_t iters);

const char *kf_backend_name(void);
const char *kf_batch_name(void);
const char *kf_chain_name(void);

#endif
