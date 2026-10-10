#include "keccak-fast.h"

#include <string.h>

#include "keccak-fast-internal.h"

#define KF_RATE(bits) (200 - ((bits) / 4))
#define KF_DOMAIN_SHAKE 0x1f
#define KF_DOMAIN_SHA3  0x06

kf_hash_fn kf_shake128 = kf_scalar_shake128;
kf_hash_fn kf_shake256 = kf_scalar_shake256;
kf_hash_fn kf_sha3_224 = kf_scalar_sha3_224;
kf_hash_fn kf_sha3_256 = kf_scalar_sha3_256;
kf_hash_fn kf_sha3_384 = kf_scalar_sha3_384;
kf_hash_fn kf_sha3_512 = kf_scalar_sha3_512;

int         kf_backend_priority = KF_PRIO_SCALAR;
const char *kf_backend_label    = "scalar";

kf_batch_perm_fn kf_batch_perm     = kf_scalar_batch;
int              kf_batch_priority = KF_PRIO_SCALAR;
int              kf_batch_lanes    = 1;
const char      *kf_batch_label    = "scalar";

const char *kf_backend_name(void) {
  return kf_backend_label;
}

const char *kf_batch_name(void) {
  return kf_batch_label;
}

static void kf_wipe(void *p, size_t n) {
  static void *(*const volatile fn)(void *, int, size_t) = memset;
  fn(p, 0, n);
}

static void kf_sponge_group(const uint8_t *in, size_t inlen, uint8_t *out,
                            size_t outlen, size_t base, size_t count,
                            size_t rate, uint8_t delim) {
  uint64_t       states[KF_LANES_MAX][25] = {0};
  uint8_t       *a                        = (uint8_t *)states;
  const uint8_t *p[KF_LANES_MAX];
  uint8_t       *o[KF_LANES_MAX];

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
    kf_batch_perm(states, count);
    remaining -= rate;
  }

  for (size_t i = 0; i < count; i++) {
    for (size_t j = 0; j < remaining; j++) a[i * 200 + j] ^= p[i][j];
    a[i * 200 + remaining] ^= delim;
    a[i * 200 + rate - 1] ^= 0x80;
  }
  kf_batch_perm(states, count);

  size_t outrem = outlen;
  while (outrem >= rate) {
    for (size_t i = 0; i < count; i++) {
      memcpy(o[i], a + i * 200, rate);
      o[i] += rate;
    }
    outrem -= rate;
    kf_batch_perm(states, count);
  }
  for (size_t i = 0; i < count; i++) {
    memcpy(o[i], a + i * 200, outrem);
  }

  kf_wipe(states, sizeof states);
}

static int kf_batch_impl(kf_hash_fn one, size_t count, const uint8_t *in,
                         size_t inlen, uint8_t *out, size_t outlen,
                         size_t rate, uint8_t delim) {
  if (count == 0) return 0;
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= 200)) return -1;

  int lanes = kf_batch_lanes;
  if (lanes > KF_LANES_MAX) lanes = KF_LANES_MAX;

  size_t base = 0;
  if (lanes > 1) {
    size_t l = (size_t)lanes;
    for (; base + l <= count; base += l) {
      kf_sponge_group(in, inlen, out, outlen, base, l, rate, delim);
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
    return kf_batch_impl(kf_shake##bits, count, in, inlen, out, outlen,        \
                         KF_RATE(bits), KF_DOMAIN_SHAKE);                      \
  }
#define KF_DEFSHA3_BATCH(bits)                                                 \
  int kf_sha3_##bits##_batch(size_t count, const uint8_t *in, size_t inlen,    \
                             uint8_t *out, size_t outlen) {                    \
    if (outlen > ((bits) / 8)) return -1;                                      \
    return kf_batch_impl(kf_sha3_##bits, count, in, inlen, out, outlen,        \
                         KF_RATE(bits), KF_DOMAIN_SHA3);                       \
  }

KF_DEFSHAKE_BATCH(128)
KF_DEFSHAKE_BATCH(256)
KF_DEFSHA3_BATCH(224)
KF_DEFSHA3_BATCH(256)
KF_DEFSHA3_BATCH(384)
KF_DEFSHA3_BATCH(512)
