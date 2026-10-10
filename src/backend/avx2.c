#include <stddef.h>
#include <stdint.h>

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

__attribute__((target("avx2")))
static void kf_permute_x4(uint64_t s[4][25]) {
  __m256i  v[25];
  __m256i  t[4];
  uint64_t tail[4];

/* 4x4 transpose of 64-bit elements: 4 unpack + 4 lane permute. */
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

  KF_LOAD4(0);
  KF_LOAD4(4);
  KF_LOAD4(8);
  KF_LOAD4(12);
  KF_LOAD4(16);
  KF_LOAD4(20);
  v[24] = _mm256_set_epi64x((long long)s[3][24], (long long)s[2][24],
                            (long long)s[1][24], (long long)s[0][24]);

#undef KF_LOAD4

  for (int i = 0; i < 24; i++) kf_avx2_round_x4(v, RC[i]);

#define KF_STORE4(B)                                                           \
  do {                                                                         \
    for (int j = 0; j < 4; j++) t[j] = v[(B) + j];                             \
    KF_TRANSPOSE4(t);                                                          \
    for (int i = 0; i < 4; i++) {                                              \
      _mm256_storeu_si256((void *)(s[i] + (B)), t[i]);                         \
    }                                                                          \
  } while (0)

  KF_STORE4(0);
  KF_STORE4(4);
  KF_STORE4(8);
  KF_STORE4(12);
  KF_STORE4(16);
  KF_STORE4(20);

#undef KF_STORE4
#undef KF_TRANSPOSE4

  _mm256_storeu_si256((void *)tail, v[24]);
  for (int i = 0; i < 4; i++) s[i][24] = tail[i];
}

__attribute__((target("avx2")))
static void kf_permute_x4_12(uint64_t s[4][25]) {
  __m256i  v[25];
  uint64_t tmp[4];

  for (int j = 0; j < 25; j++) {
    for (int i = 0; i < 4; i++) tmp[i] = s[i][j];
    v[j] = _mm256_loadu_si256((const __m256i *)tmp);
  }
  for (int i = 12; i < 24; i++) kf_avx2_round_x4(v, RC[i]);
  for (int j = 0; j < 25; j++) {
    _mm256_storeu_si256((__m256i *)tmp, v[j]);
    for (int i = 0; i < 4; i++) s[i][j] = tmp[i];
  }
}

__attribute__((target("avx2")))
void kf_avx2_batch(uint64_t states[][25], size_t count) {
  size_t i = 0;
  for (; i + 4 <= count; i += 4) {
    kf_permute_x4(&states[i]);
  }
  for (; i < count; i++) {
    kf_scalar_permute(states[i]);
  }
}

__attribute__((target("avx2")))
void kf_avx2_batch12(uint64_t states[][25], size_t count) {
  size_t i = 0;
  for (; i + 4 <= count; i += 4) {
    kf_permute_x4_12(&states[i]);
  }
  if (i < count) kf_scalar_batch12(&states[i], count - i);
}

__attribute__((constructor)) static void kf_avx2_register(void) {
  if (!__builtin_cpu_supports("avx2")) {
    return;
  }
  if (kf_batch_priority <= KF_PRIO_AVX2) {
    kf_batch_perm     = kf_avx2_batch;
    kf_batch_perm12   = kf_avx2_batch12;
    kf_batch_priority = KF_PRIO_AVX2;
    kf_batch_lanes    = 4;
    kf_batch_label    = "avx2";
  }
}

#endif
