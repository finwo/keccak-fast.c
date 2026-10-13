#ifndef FINWO_KECCAK_FAST_INTERNAL_H
#define FINWO_KECCAK_FAST_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "keccak-fast.h"

typedef void (*kf_batch_perm_fn)(uint64_t states[][25], size_t count);

typedef void (*kf_chain_fn)(size_t count, uint8_t *x, size_t outlen,
                            const uint8_t *tail, size_t tail_len,
                            size_t ctr_len, uint8_t ctr0, uint32_t iters,
                            size_t rate, uint8_t delim);

extern kf_batch_perm_fn kf_batch_perm;
extern kf_batch_perm_fn kf_batch_perm12;
extern int              kf_batch_priority;
extern int              kf_batch_lanes;

extern kf_chain_fn kf_chain_kernel;
extern kf_chain_fn kf_chain_kernel12;
extern int         kf_chain_priority;
extern int         kf_chain_lanes;

extern int         kf_backend_priority;
extern const char *kf_backend_label;
extern const char *kf_batch_label;
extern const char *kf_chain_label;

static inline void kf_chain_fill(uint64_t st[25], const uint8_t *x,
                                 size_t outlen, const uint8_t *tail,
                                 size_t tail_len, size_t ctr_len, uint8_t ctr,
                                 size_t rate, uint8_t delim) {
  uint8_t *b = (uint8_t *)st;
  memset(st, 0, 200);
  if (x != NULL) {
    memcpy(b, x, outlen);
  }
  if (tail_len != 0) {
    memcpy(b + outlen, tail, tail_len);
  }
  if (ctr_len != 0) {
    b[outlen + tail_len] = ctr;
  }
  b[outlen + tail_len + ctr_len] ^= delim;
  b[rate - 1] ^= 0x80;
}

#endif
