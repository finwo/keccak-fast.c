#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../keccak-fast-internal.h"

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_AVX2)

#include <immintrin.h>

static const uint64_t RC[24] = {
  1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
  0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
  0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
  0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

#define KF_ROL64(x, n) \
  _mm256_or_si256(_mm256_slli_epi64((x), (n)), _mm256_srli_epi64((x), 64 - (n)))

__attribute__((target("avx2"), always_inline))
static inline void kf_avx2_round_x4(__m256i v[25], uint64_t rc) {
  __m256i c0, c1, c2, c3, c4;
  __m256i d0, d1, d2, d3, d4;
  __m256i t, u;

#define KF_C(x)                                                                \
  _mm256_xor_si256(_mm256_xor_si256(v[x], v[(x) + 5]),                         \
                   _mm256_xor_si256(_mm256_xor_si256(v[(x) + 10], v[(x) + 15]), \
                                    v[(x) + 20]))
  c0 = KF_C(0);
  c1 = KF_C(1);
  c2 = KF_C(2);
  c3 = KF_C(3);
  c4 = KF_C(4);
#undef KF_C

  d0 = _mm256_xor_si256(c4, KF_ROL64(c1, 1));
  d1 = _mm256_xor_si256(c0, KF_ROL64(c2, 1));
  d2 = _mm256_xor_si256(c1, KF_ROL64(c3, 1));
  d3 = _mm256_xor_si256(c2, KF_ROL64(c4, 1));
  d4 = _mm256_xor_si256(c3, KF_ROL64(c0, 1));

#define KF_ADD(x, d)                                                           \
  v[(x)]      = _mm256_xor_si256(v[(x)], (d));                                 \
  v[(x) + 5]  = _mm256_xor_si256(v[(x) + 5], (d));                             \
  v[(x) + 10] = _mm256_xor_si256(v[(x) + 10], (d));                            \
  v[(x) + 15] = _mm256_xor_si256(v[(x) + 15], (d));                            \
  v[(x) + 20] = _mm256_xor_si256(v[(x) + 20], (d));
  KF_ADD(0, d0)
  KF_ADD(1, d1)
  KF_ADD(2, d2)
  KF_ADD(3, d3)
  KF_ADD(4, d4)
#undef KF_ADD

  t = v[1];
#define KF_RHOPI4(dest, rot)    \
  do {                          \
    u       = v[dest];          \
    v[dest] = KF_ROL64(t, rot); \
    t       = u;                \
  } while (0)
  KF_RHOPI4(10, 1);
  KF_RHOPI4(7, 3);
  KF_RHOPI4(11, 6);
  KF_RHOPI4(17, 10);
  KF_RHOPI4(18, 15);
  KF_RHOPI4(3, 21);
  KF_RHOPI4(5, 28);
  KF_RHOPI4(16, 36);
  KF_RHOPI4(8, 45);
  KF_RHOPI4(21, 55);
  KF_RHOPI4(24, 2);
  KF_RHOPI4(4, 14);
  KF_RHOPI4(15, 27);
  KF_RHOPI4(23, 41);
  KF_RHOPI4(19, 56);
  KF_RHOPI4(13, 8);
  KF_RHOPI4(12, 25);
  KF_RHOPI4(2, 43);
  KF_RHOPI4(20, 62);
  KF_RHOPI4(14, 18);
  KF_RHOPI4(22, 39);
  KF_RHOPI4(9, 61);
  KF_RHOPI4(6, 20);
  KF_RHOPI4(1, 44);
#undef KF_RHOPI4

#define KF_ROW(y)                                                              \
  do {                                                                         \
    __m256i r0 = v[(y)], r1 = v[(y) + 1], r2 = v[(y) + 2], r3 = v[(y) + 3],    \
            r4 = v[(y) + 4];                                                   \
    v[(y)]     = _mm256_xor_si256(r0, _mm256_andnot_si256(r1, r2));            \
    v[(y) + 1] = _mm256_xor_si256(r1, _mm256_andnot_si256(r2, r3));            \
    v[(y) + 2] = _mm256_xor_si256(r2, _mm256_andnot_si256(r3, r4));            \
    v[(y) + 3] = _mm256_xor_si256(r3, _mm256_andnot_si256(r4, r0));            \
    v[(y) + 4] = _mm256_xor_si256(r4, _mm256_andnot_si256(r0, r1));            \
  } while (0)
  KF_ROW(0);
  KF_ROW(5);
  KF_ROW(10);
  KF_ROW(15);
  KF_ROW(20);
#undef KF_ROW

  v[0] = _mm256_xor_si256(v[0], _mm256_set1_epi64x((long long)rc));
}

/* 4x4 transpose of 64-bit elements: 4 unpack + 4 lane permute. Shared by the
   24-round and 12-round permutes; expands against the local names s, v, t and
   tail. */
#define KF_TRANSPOSE4(T)                                                       \
  do {                                                                         \
    __m256i t0 = _mm256_unpacklo_epi64((T)[0], (T)[1]);                        \
    __m256i t1 = _mm256_unpackhi_epi64((T)[0], (T)[1]);                        \
    __m256i t2 = _mm256_unpacklo_epi64((T)[2], (T)[3]);                        \
    __m256i t3 = _mm256_unpackhi_epi64((T)[2], (T)[3]);                        \
    (T)[0] = _mm256_permute2x128_si256(t0, t2, 0x20);                          \
    (T)[1] = _mm256_permute2x128_si256(t1, t3, 0x20);                          \
    (T)[2] = _mm256_permute2x128_si256(t0, t2, 0x31);                          \
    (T)[3] = _mm256_permute2x128_si256(t1, t3, 0x31);                          \
  } while (0)

#define KF_LOAD4(B)                                                            \
  do {                                                                         \
    for (int i = 0; i < 4; i++) {                                              \
      t[i] = _mm256_loadu_si256((const void *)(s[i] + (B)));                   \
    }                                                                          \
    KF_TRANSPOSE4(t);                                                          \
    for (int j = 0; j < 4; j++) v[(B) + j] = t[j];                             \
  } while (0)

#define KF_STORE4(B)                                                           \
  do {                                                                         \
    for (int j = 0; j < 4; j++) t[j] = v[(B) + j];                             \
    KF_TRANSPOSE4(t);                                                          \
    for (int i = 0; i < 4; i++) {                                              \
      _mm256_storeu_si256((void *)(s[i] + (B)), t[i]);                         \
    }                                                                          \
  } while (0)

#define KF_LOAD4_ALL()                                                         \
  do {                                                                         \
    KF_LOAD4(0);                                                               \
    KF_LOAD4(4);                                                               \
    KF_LOAD4(8);                                                               \
    KF_LOAD4(12);                                                              \
    KF_LOAD4(16);                                                              \
    KF_LOAD4(20);                                                              \
    v[24] = _mm256_set_epi64x((long long)s[3][24], (long long)s[2][24],        \
                              (long long)s[1][24], (long long)s[0][24]);       \
  } while (0)

#define KF_STORE4_ALL()                                                        \
  do {                                                                         \
    KF_STORE4(0);                                                              \
    KF_STORE4(4);                                                              \
    KF_STORE4(8);                                                              \
    KF_STORE4(12);                                                             \
    KF_STORE4(16);                                                             \
    KF_STORE4(20);                                                             \
    _mm256_storeu_si256((void *)tail, v[24]);                                  \
    for (int i = 0; i < 4; i++) s[i][24] = tail[i];                            \
  } while (0)

__attribute__((target("avx2")))
static void kf_permute_x4(uint64_t s[4][25]) {
  __m256i  v[25];
  __m256i  t[4];
  uint64_t tail[4];

  KF_LOAD4_ALL();
  for (int i = 0; i < 24; i++) kf_avx2_round_x4(v, RC[i]);
  KF_STORE4_ALL();
}

__attribute__((target("avx2")))
static void kf_permute_x4_12(uint64_t s[4][25]) {
  __m256i  v[25];
  __m256i  t[4];
  uint64_t tail[4];

  KF_LOAD4_ALL();
  for (int i = 12; i < 24; i++) kf_avx2_round_x4(v, RC[i]);
  KF_STORE4_ALL();
}

__attribute__((target("avx2")))
void kf_avx2_batch(uint64_t states[][25], size_t count) {
  size_t i = 0;
  for (; i + 4 <= count; i += 4) {
    kf_permute_x4(&states[i]);
  }
  if (i < count) {
    uint64_t tmp[4][25] = {0};
    memcpy(tmp, &states[i], (count - i) * sizeof tmp[0]);
    kf_permute_x4(tmp);
    memcpy(&states[i], tmp, (count - i) * sizeof tmp[0]);
  }
}

__attribute__((target("avx2")))
void kf_avx2_batch12(uint64_t states[][25], size_t count) {
  size_t i = 0;
  for (; i + 4 <= count; i += 4) {
    kf_permute_x4_12(&states[i]);
  }
  if (i < count) {
    uint64_t tmp[4][25] = {0};
    memcpy(tmp, &states[i], (count - i) * sizeof tmp[0]);
    kf_permute_x4_12(tmp);
    memcpy(&states[i], tmp, (count - i) * sizeof tmp[0]);
  }
}

__attribute__((target("avx2"), always_inline))
static inline void kf_avx2_xin(uint64_t s[4][25], __m256i v[25]) {
  __m256i t[4];
  KF_LOAD4_ALL();
}

__attribute__((target("avx2"), always_inline))
static inline void kf_avx2_xout(uint64_t s[4][25], __m256i v[25]) {
  __m256i  t[4];
  uint64_t tail[4];
  KF_STORE4_ALL();
}

/* The digest stays in v; only the words below it are rewritten per iteration */
#define KF_DEF_AVX2_CHAIN_X4(NAME, R0)                                         \
  __attribute__((target("avx2"))) static void NAME(                            \
      uint64_t s[4][25], uint64_t tmpl[4][25], size_t full_words,              \
      uint64_t keep_mask, size_t ctr_word, unsigned ctr_shift, size_t ctr_len, \
      uint8_t ctr0, uint32_t iters) {                                          \
    __m256i v[25];                                                             \
    __m256i tv[25];                                                            \
    __m256i km = _mm256_set1_epi64x((long long)keep_mask);                     \
    kf_avx2_xin(s, v);                                                         \
    kf_avx2_xin(tmpl, tv);                                                     \
    for (uint32_t it = 0;;) {                                                  \
      for (int r = R0; r < 24; r++) kf_avx2_round_x4(v, RC[r]);                \
      if (++it >= iters) break;                                                \
      size_t w = full_words;                                                   \
      if (keep_mask) {                                                         \
        v[w] = _mm256_or_si256(_mm256_and_si256(v[w], km), tv[w]);             \
        w++;                                                                   \
      }                                                                        \
      for (; w < 25; w++) v[w] = tv[w];                                        \
      if (ctr_len) {                                                           \
        uint64_t c = (uint64_t)(uint8_t)(ctr0 + it) << ctr_shift;              \
        v[ctr_word] =                                                          \
            _mm256_or_si256(v[ctr_word], _mm256_set1_epi64x((long long)c));    \
      }                                                                        \
    }                                                                          \
    kf_avx2_xout(s, v);                                                        \
  }

KF_DEF_AVX2_CHAIN_X4(kf_avx2_chain_x4, 0)
KF_DEF_AVX2_CHAIN_X4(kf_avx2_chain_x4_12, 12)

#define KF_DEF_AVX2_CHAIN(NAME, X4)                                            \
  __attribute__((target("avx2"))) void NAME(                                   \
      size_t count, uint8_t *x, size_t outlen, const uint8_t *tail,            \
      size_t tail_len, size_t ctr_len, uint8_t ctr0, uint32_t iters,           \
      size_t rate, uint8_t delim) {                                            \
    uint64_t s[4][25];                                                         \
    uint64_t tmpl[4][25];                                                      \
    size_t   fw   = outlen / 8;                                                \
    size_t   part = outlen % 8;                                                \
    uint64_t km   = part ? (((uint64_t)1 << (8 * part)) - 1) : 0;              \
    size_t   cw   = (outlen + tail_len) / 8;                                   \
    unsigned cs   = (unsigned)(8 * ((outlen + tail_len) % 8));                 \
    for (size_t i = 0; i < count; i += 4) {                                    \
      size_t n = count - i < 4 ? count - i : 4;                                \
      for (size_t l = 0; l < 4; l++) {                                         \
        int            live = l < n;                                           \
        const uint8_t *tr =                                                    \
            tail_len ? tail + (live ? (i + l) : 0) * tail_len : NULL;          \
        kf_chain_fill(s[l], live ? x + (i + l) * outlen : NULL, outlen, tr,    \
                      tail_len, ctr_len, ctr0, rate, delim);                   \
        kf_chain_fill(tmpl[l], NULL, outlen, tr, tail_len, ctr_len, 0, rate,   \
                      delim);                                                  \
      }                                                                        \
      X4(s, tmpl, fw, km, cw, cs, ctr_len, ctr0, iters);                       \
      for (size_t l = 0; l < n; l++) {                                         \
        memcpy(x + (i + l) * outlen, s[l], outlen);                            \
      }                                                                        \
    }                                                                          \
  }

KF_DEF_AVX2_CHAIN(kf_avx2_chain, kf_avx2_chain_x4)
KF_DEF_AVX2_CHAIN(kf_avx2_chain12, kf_avx2_chain_x4_12)

__attribute__((constructor)) static void kf_avx2_register(void) {
  if (!__builtin_cpu_supports("avx2")) {
    return;
  }
  if (kf_batch_priority <= 218) {
    kf_batch_perm     = kf_avx2_batch;
    kf_batch_perm12   = kf_avx2_batch12;
    kf_batch_priority = 218;
    kf_batch_lanes    = 4;
    kf_batch_label    = "avx2";
  }
  if (kf_chain_priority <= 265) {
    kf_chain_kernel   = kf_avx2_chain;
    kf_chain_kernel12 = kf_avx2_chain12;
    kf_chain_priority = 265;
    kf_chain_lanes    = 4;
    kf_chain_label    = "avx2";
  }
}

#endif
