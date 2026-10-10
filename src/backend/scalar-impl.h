#ifndef FINWO_SCALAR_IMPL_H
#define FINWO_SCALAR_IMPL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

static const uint8_t rho[24] = {
  1, 3, 6, 10, 15, 21,
  28, 36, 45, 55, 2, 14,
  27, 41, 56, 8, 25, 43,
  62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = {
  10, 7, 11, 17, 18, 3,
  5, 16, 8, 21, 24, 4,
  15, 23, 19, 13, 12, 2,
  20, 14, 22, 9, 6, 1};
static const uint64_t RC[24] = {
  1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
  0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
  0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
  0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;              \
  REPEAT5(e; v += s;)

static inline void keccakf(void *state) {
  uint64_t *a    = (uint64_t *)state;
  uint64_t  b[5] = {0};
  uint64_t  t    = 0;
  uint8_t   x, y;

  for (int i = 0; i < 24; i++) {
    /* theta */
    FOR5(x, 1, b[x] = 0; FOR5(y, 5, b[x] ^= a[x + y];))
    FOR5(x, 1, FOR5(y, 5, a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);))
    /* rho and pi */
    t = a[1];
    x = 0;
    REPEAT24(b[0] = a[pi[x]];
             a[pi[x]] = rol(t, rho[x]);
             t = b[0];
             x++;)
    /* chi */
    FOR5(y,
         5,
         FOR5(x, 1, b[x] = a[y + x];)
         FOR5(x, 1, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);))
    /* iota */
    a[0] ^= RC[i];
  }
}

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

#define foldP(I, L, F) \
  while (L >= rate) {  \
    F(a, I, rate);     \
    keccakf(a);        \
    I += rate;         \
    L -= rate;         \
  }

static inline int kf_hash_impl(uint8_t *out, size_t outlen,
                               const uint8_t *in, size_t inlen,
                               size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
    return -1;
  }
  uint8_t a[Plen] = {0};
  foldP(in, inlen, xorin);
  a[inlen] ^= delim;
  a[rate - 1] ^= 0x80;
  xorin(a, in, inlen);
  keccakf(a);
  foldP(out, outlen, setout);
  setout(a, out, outlen);
  memset_s(a, 200, 0, 200);
  return 0;
}

#define defshake(bits)                                                         \
  KF_LINKAGE int KF_FN(shake##bits)(uint8_t *out, size_t outlen,               \
                                    const uint8_t *in, size_t inlen) {         \
    return kf_hash_impl(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);       \
  }
#define defsha3(bits)                                                          \
  KF_LINKAGE int KF_FN(sha3_##bits)(uint8_t *out, size_t outlen,               \
                                   const uint8_t *in, size_t inlen) {          \
    if (outlen > (bits / 8)) {                                                 \
      return -1;                                                               \
    }                                                                          \
    return kf_hash_impl(out, outlen, in, inlen, 200 - (bits / 4), 0x06);       \
  }

defshake(128)
defshake(256)
defsha3(224)
defsha3(256)
defsha3(384)
defsha3(512)

#undef defshake
#undef defsha3

#endif /* FINWO_SCALAR_IMPL_H */
