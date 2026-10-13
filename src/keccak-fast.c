#include "keccak-fast.h"

#include <string.h>

#include "keccak-fast-internal.h"

#define KF_RATE(bits) (200 - ((bits) / 4))
#define KF_DOMAIN_SHAKE 0x1f
#define KF_DOMAIN_SHA3  0x06

kf_hash_fn kf_shake128 = NULL;
kf_hash_fn kf_shake256 = NULL;
kf_hash_fn kf_sha3_224 = NULL;
kf_hash_fn kf_sha3_256 = NULL;
kf_hash_fn kf_sha3_384 = NULL;
kf_hash_fn kf_sha3_512 = NULL;
kf_hash_fn kf_turboshake128 = NULL;
kf_hash_fn kf_turboshake256 = NULL;

int         kf_backend_priority = 0;
const char *kf_backend_label    = "none";

kf_batch_perm_fn kf_batch_perm     = NULL;
kf_batch_perm_fn kf_batch_perm12   = NULL;
int              kf_batch_priority = 0;
int              kf_batch_lanes    = 1;
const char      *kf_batch_label    = "none";

kf_chain_fn kf_chain_kernel   = NULL;
kf_chain_fn kf_chain_kernel12 = NULL;
int         kf_chain_priority = 0;
int         kf_chain_lanes    = 1;
const char *kf_chain_label    = "none";

const char *kf_backend_name(void) {
  return kf_backend_label;
}

const char *kf_batch_name(void) {
  return kf_batch_label;
}

const char *kf_chain_name(void) {
  return kf_chain_label;
}

static void kf_wipe(void *p, size_t n) {
  static void *(*const volatile fn)(void *, int, size_t) = memset;
  fn(p, 0, n);
}

static void kf_sponge_group(kf_batch_perm_fn perm, const uint8_t *in,
                            size_t inlen, uint8_t *out, size_t outlen,
                            size_t base, size_t count, size_t rate,
                            uint8_t delim) {
  uint64_t       states[count][25];
  uint8_t       *a = (uint8_t *)states;
  const uint8_t *p[count];
  uint8_t       *o[count];

  memset(states, 0, sizeof states);

  for (size_t i = 0; i < count; i++) {
    p[i] = in + (base + i) * inlen;
    o[i] = out + (base + i) * outlen;
  }

  size_t remaining = inlen;
  while (remaining >= rate) {
    for (size_t i = 0; i < count; i++) {
      for (size_t j = 0; j < rate; j++) a[i * 200 + j] ^= p[i][j];
      p[i] += rate;
    }
    perm(states, count);
    remaining -= rate;
  }

  for (size_t i = 0; i < count; i++) {
    for (size_t j = 0; j < remaining; j++) a[i * 200 + j] ^= p[i][j];
    a[i * 200 + remaining] ^= delim;
    a[i * 200 + rate - 1] ^= 0x80;
  }
  perm(states, count);

  size_t outrem = outlen;
  while (outrem >= rate) {
    for (size_t i = 0; i < count; i++) {
      memcpy(o[i], a + i * 200, rate);
      o[i] += rate;
    }
    outrem -= rate;
    perm(states, count);
  }
  for (size_t i = 0; i < count; i++) {
    memcpy(o[i], a + i * 200, outrem);
  }

  kf_wipe(states, sizeof states);
}

static int kf_batch_impl(kf_hash_fn one, kf_batch_perm_fn perm, size_t count,
                         const uint8_t *in, size_t inlen, uint8_t *out,
                         size_t outlen, size_t rate, uint8_t delim) {
  if (count == 0) return 0;
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= 200)) return -1;

  int lanes = kf_batch_lanes;

  size_t base = 0;
  if (lanes > 1) {
    size_t l = (size_t)lanes;
    for (; base + l <= count; base += l) {
      kf_sponge_group(perm, in, inlen, out, outlen, base, l, rate, delim);
    }
  }
  for (; base < count; base++) {
    one(out + base * outlen, outlen, in + base * inlen, inlen);
  }
  return 0;
}

#define KF_DEFSHAKE_BATCH(bits)                                                \
  int kf_shake##bits##_batch(size_t count, const uint8_t *in, size_t inlen,    \
                             uint8_t *out, size_t outlen) {                    \
    return kf_batch_impl(kf_shake##bits, kf_batch_perm, count, in, inlen, out, \
                         outlen, KF_RATE(bits), KF_DOMAIN_SHAKE);              \
  }
#define KF_DEFSHA3_BATCH(bits)                                                 \
  int kf_sha3_##bits##_batch(size_t count, const uint8_t *in, size_t inlen,    \
                             uint8_t *out, size_t outlen) {                    \
    if (outlen > ((bits) / 8)) return -1;                                      \
    return kf_batch_impl(kf_sha3_##bits, kf_batch_perm, count, in, inlen, out, \
                         outlen, KF_RATE(bits), KF_DOMAIN_SHA3);               \
  }
#define KF_DEFTURBOSHAKE_BATCH(bits)                                           \
  int kf_turboshake##bits##_batch(size_t count, const uint8_t *in,             \
                                  size_t inlen, uint8_t *out, size_t outlen) { \
    return kf_batch_impl(kf_turboshake##bits, kf_batch_perm12, count, in,      \
                         inlen, out, outlen, KF_RATE(bits), KF_DOMAIN_SHAKE);  \
  }

KF_DEFSHAKE_BATCH(128)
KF_DEFSHAKE_BATCH(256)
KF_DEFSHA3_BATCH(224)
KF_DEFSHA3_BATCH(256)
KF_DEFSHA3_BATCH(384)
KF_DEFSHA3_BATCH(512)
KF_DEFTURBOSHAKE_BATCH(128)
KF_DEFTURBOSHAKE_BATCH(256)

static int kf_chain_impl(kf_chain_fn kernel, size_t count, uint8_t *x,
                         size_t outlen, const uint8_t *tail, size_t tail_len,
                         size_t ctr_len, uint8_t ctr0, uint32_t iters,
                         size_t rate, uint8_t delim) {
  if ((x == NULL) || ((tail == NULL) && (tail_len != 0))) return -1;
  if ((outlen == 0) || (ctr_len > 1) || (rate >= 200)) return -1;
  if (outlen + tail_len + ctr_len > rate - 1) return -1;
  if ((kernel == NULL) || (kf_chain_lanes <= 0)) return -1;
  if ((count == 0) || (iters == 0)) return 0;
  kernel(count, x, outlen, tail, tail_len, ctr_len, ctr0, iters, rate, delim);
  return 0;
}

#define KF_DEFSHAKE_CHAIN(bits)                                                \
  int kf_shake##bits##_chain(size_t count, uint8_t *x, size_t outlen,          \
                             const uint8_t *tail, size_t tail_len,             \
                             size_t ctr_len, uint8_t ctr0, uint32_t iters) {   \
    return kf_chain_impl(kf_chain_kernel, count, x, outlen, tail, tail_len,    \
                         ctr_len, ctr0, iters, KF_RATE(bits),                  \
                         KF_DOMAIN_SHAKE);                                     \
  }
#define KF_DEFSHA3_CHAIN(bits)                                                 \
  int kf_sha3_##bits##_chain(size_t count, uint8_t *x, size_t outlen,          \
                             const uint8_t *tail, size_t tail_len,             \
                             size_t ctr_len, uint8_t ctr0, uint32_t iters) {   \
    if (outlen > ((bits) / 8)) return -1;                                      \
    return kf_chain_impl(kf_chain_kernel, count, x, outlen, tail, tail_len,    \
                         ctr_len, ctr0, iters, KF_RATE(bits),                  \
                         KF_DOMAIN_SHA3);                                      \
  }
#define KF_DEFTURBOSHAKE_CHAIN(bits)                                           \
  int kf_turboshake##bits##_chain(size_t count, uint8_t *x, size_t outlen,     \
                                  const uint8_t *tail, size_t tail_len,        \
                                  size_t ctr_len, uint8_t ctr0,                \
                                  uint32_t iters) {                            \
    return kf_chain_impl(kf_chain_kernel12, count, x, outlen, tail, tail_len,  \
                         ctr_len, ctr0, iters, KF_RATE(bits),                  \
                         KF_DOMAIN_SHAKE);                                     \
  }

KF_DEFSHAKE_CHAIN(128)
KF_DEFSHAKE_CHAIN(256)
KF_DEFSHA3_CHAIN(224)
KF_DEFSHA3_CHAIN(256)
KF_DEFSHA3_CHAIN(384)
KF_DEFSHA3_CHAIN(512)
KF_DEFTURBOSHAKE_CHAIN(128)
KF_DEFTURBOSHAKE_CHAIN(256)
