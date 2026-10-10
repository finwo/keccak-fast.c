#ifndef FINWO_KECCAK_FAST_INTERNAL_H
#define FINWO_KECCAK_FAST_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "keccak-fast.h"

typedef void (*kf_batch_perm_fn)(uint64_t states[][25], size_t count);

#define KF_LANES_MAX 8

#define KF_PRIO_SCALAR  0
#define KF_PRIO_BMI    10
#define KF_PRIO_AVX2   20
#define KF_PRIO_AVX512 30

extern kf_batch_perm_fn kf_batch_perm;
extern int              kf_batch_priority;
extern int              kf_batch_lanes;

extern int         kf_backend_priority;
extern const char *kf_backend_label;
extern const char *kf_batch_label;

int kf_scalar_shake128(uint8_t *out, size_t outlen, const uint8_t *in,
                       size_t inlen);
int kf_scalar_shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                       size_t inlen);
int kf_scalar_sha3_224(uint8_t *out, size_t outlen, const uint8_t *in,
                       size_t inlen);
int kf_scalar_sha3_256(uint8_t *out, size_t outlen, const uint8_t *in,
                       size_t inlen);
int kf_scalar_sha3_384(uint8_t *out, size_t outlen, const uint8_t *in,
                       size_t inlen);
int kf_scalar_sha3_512(uint8_t *out, size_t outlen, const uint8_t *in,
                       size_t inlen);
int kf_scalar_turboshake128(uint8_t *out, size_t outlen, const uint8_t *in,
                            size_t inlen);
int kf_scalar_turboshake256(uint8_t *out, size_t outlen, const uint8_t *in,
                            size_t inlen);
void kf_scalar_permute(uint64_t state[25]);
void kf_scalar_batch(uint64_t states[][25], size_t count);

#endif
