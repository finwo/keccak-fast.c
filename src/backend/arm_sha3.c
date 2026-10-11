/* ARMv8.2 SHA3 backend. Self-contained: own permutation (arm-sha3-perm.h)
 * and own copy of the FIPS 202 sponge. Nothing here is shared with, or leaks
 * into, the scalar backend. Availability is decided at runtime only. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../keccak-fast-internal.h"

#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)

#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#ifndef HWCAP_SHA3
#define HWCAP_SHA3 (1 << 17)
#endif
#endif

/* The sha3 target is scoped to the permutation, sponge and batch kernels so
 * the runtime gate below compiles at the x86-64 baseline with no SHA3
 * instructions of its own. */
#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("sha3"))), apply_to = function)
#elif defined(__GNUC__)
#pragma GCC push_options
#pragma GCC target("+sha3")
#endif

#include <arm_neon.h>

static const uint64_t RC[24] = {
  1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
  0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
  0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
  0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

#include "arm-sha3-perm.h"

#define KF_CAT2(a, b) a##b
#define KF_CAT(a, b) KF_CAT2(a, b)
#define KF_FN(name) KF_CAT(KF_PREFIX, name)

#if !defined(__STDC_LIB_EXT1__)
static inline int memset_s(void *dest, size_t destsz, int ch, size_t count) {
  (void)destsz;
  memset(dest, ch, count);
  return 0;
}
#endif

#define _(S) do { S } while (0)
#define FOR(i, ST, L, S) \
  _(for (size_t i = 0; i < L; i += ST) { S; })
#define mkapply_ds(NAME, S) \
  static inline void NAME(uint8_t *dst, const uint8_t *src, size_t len) { \
    FOR(i, 1, len, S);                                                    \
  }
#define mkapply_sd(NAME, S) \
  static inline void NAME(const uint8_t *src, uint8_t *dst, size_t len) { \
    FOR(i, 1, len, S);                                                    \
  }

mkapply_ds(xorin, dst[i] ^= src[i])
mkapply_sd(setout, dst[i] = src[i])

#define Plen 200

#define foldP(I, L, F, PERM) \
  while (L >= rate) {      \
    F(a, I, rate);         \
    PERM(a);               \
    I += rate;             \
    L -= rate;             \
  }

#define KF_HASH_BODY(PERM)                                                     \
  uint8_t a[Plen] = {0};                                                       \
  foldP(in, inlen, xorin, PERM);                                               \
  a[inlen] ^= delim;                                                           \
  a[rate - 1] ^= 0x80;                                                         \
  xorin(a, in, inlen);                                                         \
  PERM(a);                                                                     \
  foldP(out, outlen, setout, PERM);                                            \
  setout(a, out, outlen);                                                      \
  memset_s(a, 200, 0, 200);                                                    \
  return 0

static inline int kf_hash24(uint8_t *out, size_t outlen, const uint8_t *in,
                            size_t inlen, size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
    return -1;
  }
  KF_HASH_BODY(keccakf_armsha3);
}

static inline int kf_hash12(uint8_t *out, size_t outlen, const uint8_t *in,
                            size_t inlen, size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
    return -1;
  }
  KF_HASH_BODY(keccak12_armsha3);
}

#define defshake(bits)                                                         \
  KF_LINKAGE int KF_FN(shake##bits)(uint8_t *out, size_t outlen,               \
                                    const uint8_t *in, size_t inlen) {         \
    return kf_hash24(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);          \
  }
#define defsha3(bits)                                                          \
  KF_LINKAGE int KF_FN(sha3_##bits)(uint8_t *out, size_t outlen,               \
                                   const uint8_t *in, size_t inlen) {          \
    if (outlen > (bits / 8)) {                                                 \
      return -1;                                                               \
    }                                                                          \
    return kf_hash24(out, outlen, in, inlen, 200 - (bits / 4), 0x06);          \
  }
#define defturboshake(bits)                                                    \
  KF_LINKAGE int KF_FN(turboshake##bits)(uint8_t *out, size_t outlen,          \
                                         const uint8_t *in, size_t inlen) {    \
    return kf_hash12(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);          \
  }

#define KF_PREFIX kf_armsha3_
#define KF_LINKAGE
defshake(128)
defshake(256)
defsha3(224)
defsha3(256)
defsha3(384)
defsha3(512)
defturboshake(128)
defturboshake(256)
#undef defshake
#undef defsha3
#undef defturboshake

void kf_armsha3_batch(uint64_t states[][25], size_t count) {
  size_t i = 0;
  for (; i + 2 <= count; i += 2) {
    keccakf2_armsha3(&states[i]);
  }
  for (; i < count; i++) {
    keccakf_armsha3(states[i]);
  }
}

void kf_armsha3_batch12(uint64_t states[][25], size_t count) {
  size_t i = 0;
  for (; i + 2 <= count; i += 2) {
    keccak12_2_armsha3(&states[i]);
  }
  for (; i < count; i++) {
    keccak12_armsha3(states[i]);
  }
}

#if defined(__clang__)
#pragma clang attribute pop
#elif defined(__GNUC__)
#pragma GCC pop_options
#endif

static int kf_armsha3_available(void) {
#if defined(__APPLE__)
  int    v = 0;
  size_t n = sizeof v;
  if (sysctlbyname("hw.optional.arm.FEAT_SHA3", &v, &n, NULL, 0) != 0) {
    return 0;
  }
  return v != 0;
#elif defined(__linux__)
  return (getauxval(AT_HWCAP) & HWCAP_SHA3) != 0;
#else
  return 0;
#endif
}

__attribute__((constructor)) static void kf_armsha3_register(void) {
  if (!kf_armsha3_available()) {
    return;
  }
  if (kf_backend_priority <= KF_PRIO_SHA3) {
    kf_shake128      = kf_armsha3_shake128;
    kf_shake256      = kf_armsha3_shake256;
    kf_sha3_224      = kf_armsha3_sha3_224;
    kf_sha3_256      = kf_armsha3_sha3_256;
    kf_sha3_384      = kf_armsha3_sha3_384;
    kf_sha3_512      = kf_armsha3_sha3_512;
    kf_turboshake128 = kf_armsha3_turboshake128;
    kf_turboshake256 = kf_armsha3_turboshake256;
    kf_backend_priority = KF_PRIO_SHA3;
    kf_backend_label    = "arm-sha3";
  }
  if (kf_batch_priority <= KF_PRIO_SHA3) {
    kf_batch_perm     = kf_armsha3_batch;
    kf_batch_perm12   = kf_armsha3_batch12;
    kf_batch_priority = KF_PRIO_SHA3;
    kf_batch_lanes    = 2;
    kf_batch_label    = "arm-sha3 x2";
  }
}

#endif /* aarch64 && !KECCAK_FAST_NO_SHA3 */
