#ifndef FINWO_SCALAR_IMPL_H
#define FINWO_SCALAR_IMPL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define KF_CAT2(a, b) a##b
#define KF_CAT(a, b) KF_CAT2(a, b)
#define KF_FN(name) KF_CAT(KF_PREFIX, name)

static const uint64_t RC[24] = {
  1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
  0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
  0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
  0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))

#include "scalar-perm.h"

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
  memset(a, 0, 200);                                                           \
  return 0

static inline int kf_hash24(uint8_t *out, size_t outlen, const uint8_t *in,
                            size_t inlen, size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
    return -1;
  }
  KF_HASH_BODY(keccakf);
}

static inline int kf_hash12(uint8_t *out, size_t outlen, const uint8_t *in,
                            size_t inlen, size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
    return -1;
  }
  KF_HASH_BODY(keccak12);
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

#endif /* FINWO_SCALAR_IMPL_H */
