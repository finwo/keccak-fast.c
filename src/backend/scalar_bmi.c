/* Keccak-f[1600] and the FIPS 202 sponge of coruus/keccak-tiny, renamed
 * kf_bmi_* for the dispatcher.
 *
 * Implementor: David Leon Gil. License: CC0, attribution kindly requested.
 * Blame taken too, but not liability.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../keccak-fast-internal.h"

#if (defined(__x86_64__) || defined(__i386__)) && !defined(KECCAK_FAST_NO_BMI)

/* clang schedules `rorx` worse than `rol`; gcc is faster with it. */
#if defined(__clang__)
#pragma clang attribute push(                                                  \
    __attribute__((target("no-avx,no-avx2,no-avx512f,bmi,no-bmi2"))),          \
    apply_to=function)
#elif defined(__GNUC__)
#pragma GCC target("no-avx,no-avx2,no-avx512f,bmi,bmi2")
#endif

static const uint64_t RC[24] = {
  1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
  0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
  0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
  0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))

#define KFP_LOAD(P, S) \
  P##0 = S[0]; \
  P##1 = S[1]; \
  P##2 = S[2]; \
  P##3 = S[3]; \
  P##4 = S[4]; \
  P##5 = S[5]; \
  P##6 = S[6]; \
  P##7 = S[7]; \
  P##8 = S[8]; \
  P##9 = S[9]; \
  P##10 = S[10]; \
  P##11 = S[11]; \
  P##12 = S[12]; \
  P##13 = S[13]; \
  P##14 = S[14]; \
  P##15 = S[15]; \
  P##16 = S[16]; \
  P##17 = S[17]; \
  P##18 = S[18]; \
  P##19 = S[19]; \
  P##20 = S[20]; \
  P##21 = S[21]; \
  P##22 = S[22]; \
  P##23 = S[23]; \
  P##24 = S[24]; \

#define KFP_STORE(S, P) \
  S[0] = P##0; \
  S[1] = P##1; \
  S[2] = P##2; \
  S[3] = P##3; \
  S[4] = P##4; \
  S[5] = P##5; \
  S[6] = P##6; \
  S[7] = P##7; \
  S[8] = P##8; \
  S[9] = P##9; \
  S[10] = P##10; \
  S[11] = P##11; \
  S[12] = P##12; \
  S[13] = P##13; \
  S[14] = P##14; \
  S[15] = P##15; \
  S[16] = P##16; \
  S[17] = P##17; \
  S[18] = P##18; \
  S[19] = P##19; \
  S[20] = P##20; \
  S[21] = P##21; \
  S[22] = P##22; \
  S[23] = P##23; \
  S[24] = P##24; \

#define KFP_INIT_C(SRC) \
  c0 = SRC##0 ^ SRC##5 ^ SRC##10 ^ SRC##15 ^ SRC##20; \
  c1 = SRC##1 ^ SRC##6 ^ SRC##11 ^ SRC##16 ^ SRC##21; \
  c2 = SRC##2 ^ SRC##7 ^ SRC##12 ^ SRC##17 ^ SRC##22; \
  c3 = SRC##3 ^ SRC##8 ^ SRC##13 ^ SRC##18 ^ SRC##23; \
  c4 = SRC##4 ^ SRC##9 ^ SRC##14 ^ SRC##19 ^ SRC##24; \

#define KFP_R(SRC, DST, RCIDX) \
  d0 = c4 ^ rol(c1, 1); \
  d1 = c0 ^ rol(c2, 1); \
  d2 = c1 ^ rol(c3, 1); \
  d3 = c2 ^ rol(c4, 1); \
  d4 = c3 ^ rol(c0, 1); \
  SRC##0 ^= d0; \
  b0 = SRC##0; \
  SRC##6 ^= d1; \
  b1 = rol(SRC##6, 44); \
  SRC##12 ^= d2; \
  b2 = rol(SRC##12, 43); \
  SRC##18 ^= d3; \
  b3 = rol(SRC##18, 21); \
  SRC##24 ^= d4; \
  b4 = rol(SRC##24, 14); \
  DST##0 = b0 ^ ((~b1) & b2); \
  DST##1 = b1 ^ ((~b2) & b3); \
  DST##2 = b2 ^ ((~b3) & b4); \
  DST##3 = b3 ^ ((~b4) & b0); \
  DST##4 = b4 ^ ((~b0) & b1); \
  DST##0 ^= RC[RCIDX]; \
  c0 = DST##0; \
  c1 = DST##1; \
  c2 = DST##2; \
  c3 = DST##3; \
  c4 = DST##4; \
  SRC##3 ^= d3; \
  b5 = rol(SRC##3, 28); \
  SRC##9 ^= d4; \
  b6 = rol(SRC##9, 20); \
  SRC##10 ^= d0; \
  b7 = rol(SRC##10, 3); \
  SRC##16 ^= d1; \
  b8 = rol(SRC##16, 45); \
  SRC##22 ^= d2; \
  b9 = rol(SRC##22, 61); \
  DST##5 = b5 ^ ((~b6) & b7); \
  DST##6 = b6 ^ ((~b7) & b8); \
  DST##7 = b7 ^ ((~b8) & b9); \
  DST##8 = b8 ^ ((~b9) & b5); \
  DST##9 = b9 ^ ((~b5) & b6); \
  c0 ^= DST##5; \
  c1 ^= DST##6; \
  c2 ^= DST##7; \
  c3 ^= DST##8; \
  c4 ^= DST##9; \
  SRC##1 ^= d1; \
  b10 = rol(SRC##1, 1); \
  SRC##7 ^= d2; \
  b11 = rol(SRC##7, 6); \
  SRC##13 ^= d3; \
  b12 = rol(SRC##13, 25); \
  SRC##19 ^= d4; \
  b13 = rol(SRC##19, 8); \
  SRC##20 ^= d0; \
  b14 = rol(SRC##20, 18); \
  DST##10 = b10 ^ ((~b11) & b12); \
  DST##11 = b11 ^ ((~b12) & b13); \
  DST##12 = b12 ^ ((~b13) & b14); \
  DST##13 = b13 ^ ((~b14) & b10); \
  DST##14 = b14 ^ ((~b10) & b11); \
  c0 ^= DST##10; \
  c1 ^= DST##11; \
  c2 ^= DST##12; \
  c3 ^= DST##13; \
  c4 ^= DST##14; \
  SRC##4 ^= d4; \
  b15 = rol(SRC##4, 27); \
  SRC##5 ^= d0; \
  b16 = rol(SRC##5, 36); \
  SRC##11 ^= d1; \
  b17 = rol(SRC##11, 10); \
  SRC##17 ^= d2; \
  b18 = rol(SRC##17, 15); \
  SRC##23 ^= d3; \
  b19 = rol(SRC##23, 56); \
  DST##15 = b15 ^ ((~b16) & b17); \
  DST##16 = b16 ^ ((~b17) & b18); \
  DST##17 = b17 ^ ((~b18) & b19); \
  DST##18 = b18 ^ ((~b19) & b15); \
  DST##19 = b19 ^ ((~b15) & b16); \
  c0 ^= DST##15; \
  c1 ^= DST##16; \
  c2 ^= DST##17; \
  c3 ^= DST##18; \
  c4 ^= DST##19; \
  SRC##2 ^= d2; \
  b20 = rol(SRC##2, 62); \
  SRC##8 ^= d3; \
  b21 = rol(SRC##8, 55); \
  SRC##14 ^= d4; \
  b22 = rol(SRC##14, 39); \
  SRC##15 ^= d0; \
  b23 = rol(SRC##15, 41); \
  SRC##21 ^= d1; \
  b24 = rol(SRC##21, 2); \
  DST##20 = b20 ^ ((~b21) & b22); \
  DST##21 = b21 ^ ((~b22) & b23); \
  DST##22 = b22 ^ ((~b23) & b24); \
  DST##23 = b23 ^ ((~b24) & b20); \
  DST##24 = b24 ^ ((~b20) & b21); \
  c0 ^= DST##20; \
  c1 ^= DST##21; \
  c2 ^= DST##22; \
  c3 ^= DST##23; \
  c4 ^= DST##24; \

#define KFP_R2(SRC, DST, I) KFP_R(SRC, DST, I) KFP_R(DST, SRC, I + 1)
#define KFP_R4(SRC, DST, I) KFP_R2(SRC, DST, I) KFP_R2(SRC, DST, I + 2)

#define KFP_DECL(P)                                                            \
  uint64_t P##0, P##1, P##2, P##3, P##4, P##5, P##6, P##7, P##8, P##9,         \
      P##10, P##11, P##12, P##13, P##14, P##15, P##16, P##17, P##18, P##19,    \
      P##20, P##21, P##22, P##23, P##24

#define KFP_BODY(ROUNDS)                                                       \
  uint64_t *s = (uint64_t *)state;                                             \
  KFP_DECL(a);                                                                 \
  KFP_DECL(e);                                                                 \
  KFP_DECL(b);                                                                 \
  uint64_t c0, c1, c2, c3, c4, d0, d1, d2, d3, d4;                             \
  KFP_LOAD(a, s)                                                               \
  KFP_INIT_C(a)                                                                \
  ROUNDS                                                                       \
  KFP_STORE(s, a)

static inline void keccakf(void *state) {
  KFP_BODY(for (int i = 0; i < 24; i += 4) { KFP_R4(a, e, i) })
}

static inline void keccak12(void *state) {
  KFP_BODY(for (int i = 12; i < 24; i += 4) { KFP_R4(a, e, i) })
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

#define KF_CAT2(a, b) a##b
#define KF_CAT(a, b) KF_CAT2(a, b)
#define KF_FN(name) KF_CAT(KF_PREFIX, name)
#define KF_PREFIX kf_bmi_

#define defshake(bits)                                                         \
  int KF_FN(shake##bits)(uint8_t *out, size_t outlen,                          \
                         const uint8_t *in, size_t inlen) {                    \
    return kf_hash24(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);          \
  }
#define defsha3(bits)                                                          \
  int KF_FN(sha3_##bits)(uint8_t *out, size_t outlen,                          \
                         const uint8_t *in, size_t inlen) {                    \
    if (outlen > (bits / 8)) {                                                 \
      return -1;                                                               \
    }                                                                          \
    return kf_hash24(out, outlen, in, inlen, 200 - (bits / 4), 0x06);          \
  }
#define defturboshake(bits)                                                    \
  int KF_FN(turboshake##bits)(uint8_t *out, size_t outlen,                     \
                              const uint8_t *in, size_t inlen) {               \
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

void kf_bmi_batch(uint64_t states[][25], size_t count) {
  for (size_t i = 0; i < count; i++) {
    keccakf(states[i]);
  }
}

void kf_bmi_batch12(uint64_t states[][25], size_t count) {
  for (size_t i = 0; i < count; i++) {
    keccak12(states[i]);
  }
}

#define KF_DEFBMICHAIN(NAME, PERM)                                             \
  void NAME(size_t count, uint8_t *x, size_t outlen, const uint8_t *tail,      \
            size_t tail_len, size_t ctr_len, uint8_t ctr0, uint32_t iters,     \
            size_t rate, uint8_t delim) {                                      \
    uint64_t st[25];                                                           \
    for (size_t r = 0; r < count; r++) {                                       \
      uint8_t       *xr = x + r * outlen;                                      \
      const uint8_t *tr = tail_len ? tail + r * tail_len : NULL;               \
      for (uint32_t it = 0; it < iters; it++) {                                \
        kf_chain_fill(st, xr, outlen, tr, tail_len, ctr_len,                   \
                      (uint8_t)(ctr0 + it), rate, delim);                      \
        PERM(st);                                                              \
        memcpy(xr, st, outlen);                                                \
      }                                                                        \
    }                                                                          \
  }

KF_DEFBMICHAIN(kf_bmi_chain, keccakf)
KF_DEFBMICHAIN(kf_bmi_chain12, keccak12)

#undef KF_DEFBMICHAIN

__attribute__((constructor)) static void kf_bmi_register(void) {
#if defined(__clang__)
  if (!__builtin_cpu_supports("bmi")) {
#else
  if (!__builtin_cpu_supports("bmi") || !__builtin_cpu_supports("bmi2")) {
#endif
    return;
  }
  if (kf_backend_priority <= 115) {
    kf_shake128 = kf_bmi_shake128;
    kf_shake256 = kf_bmi_shake256;
    kf_sha3_224 = kf_bmi_sha3_224;
    kf_sha3_256 = kf_bmi_sha3_256;
    kf_sha3_384 = kf_bmi_sha3_384;
    kf_sha3_512 = kf_bmi_sha3_512;
    kf_turboshake128 = kf_bmi_turboshake128;
    kf_turboshake256 = kf_bmi_turboshake256;
    kf_backend_priority = 115;
    kf_backend_label    = "scalar+bmi";
  }
  if (kf_batch_priority <= 114) {
    kf_batch_perm     = kf_bmi_batch;
    kf_batch_perm12   = kf_bmi_batch12;
    kf_batch_priority = 114;
    kf_batch_lanes    = 1;
    kf_batch_label    = "scalar+bmi";
  }
  if (kf_chain_priority <= 114) {
    kf_chain_kernel   = kf_bmi_chain;
    kf_chain_kernel12 = kf_bmi_chain12;
    kf_chain_priority = 114;
    kf_chain_lanes    = 1;
    kf_chain_label    = "scalar+bmi";
  }
}

#if defined(__clang__)
#pragma clang attribute pop
#endif

#endif
