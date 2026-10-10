#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#include "../keccak-fast-internal.h"

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_AVX512)

static const uint64_t RC[24] = {
  1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
  0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
  0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
  0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

__attribute__((target("avx512f"), always_inline))
static inline void kf_avx512_round_x8(__m512i v[25], uint64_t rc) {
  __m512i c0, c1, c2, c3, c4;
  __m512i d0, d1, d2, d3, d4;
  __m512i t, u;

#define KF_C(x)                                                                \
  _mm512_ternarylogic_epi64(                                                   \
    _mm512_ternarylogic_epi64(v[x], v[(x) + 5], v[(x) + 10], 0x96),            \
    v[(x) + 15], v[(x) + 20], 0x96)
  c0 = KF_C(0);
  c1 = KF_C(1);
  c2 = KF_C(2);
  c3 = KF_C(3);
  c4 = KF_C(4);
#undef KF_C

  d0 = _mm512_xor_si512(c4, _mm512_rol_epi64(c1, 1));
  d1 = _mm512_xor_si512(c0, _mm512_rol_epi64(c2, 1));
  d2 = _mm512_xor_si512(c1, _mm512_rol_epi64(c3, 1));
  d3 = _mm512_xor_si512(c2, _mm512_rol_epi64(c4, 1));
  d4 = _mm512_xor_si512(c3, _mm512_rol_epi64(c0, 1));

#define KF_ADD(x, d)                                                           \
  v[(x)]      = _mm512_xor_si512(v[(x)], (d));                                 \
  v[(x) + 5]  = _mm512_xor_si512(v[(x) + 5], (d));                             \
  v[(x) + 10] = _mm512_xor_si512(v[(x) + 10], (d));                            \
  v[(x) + 15] = _mm512_xor_si512(v[(x) + 15], (d));                            \
  v[(x) + 20] = _mm512_xor_si512(v[(x) + 20], (d));
  KF_ADD(0, d0)
  KF_ADD(1, d1)
  KF_ADD(2, d2)
  KF_ADD(3, d3)
  KF_ADD(4, d4)
#undef KF_ADD

  t = v[1];
#define KF_RHOPI8(dest, rot)               \
  do {                                     \
    u       = v[dest];                     \
    v[dest] = _mm512_rol_epi64(t, rot);    \
    t       = u;                           \
  } while (0)
  KF_RHOPI8(10, 1);
  KF_RHOPI8(7, 3);
  KF_RHOPI8(11, 6);
  KF_RHOPI8(17, 10);
  KF_RHOPI8(18, 15);
  KF_RHOPI8(3, 21);
  KF_RHOPI8(5, 28);
  KF_RHOPI8(16, 36);
  KF_RHOPI8(8, 45);
  KF_RHOPI8(21, 55);
  KF_RHOPI8(24, 2);
  KF_RHOPI8(4, 14);
  KF_RHOPI8(15, 27);
  KF_RHOPI8(23, 41);
  KF_RHOPI8(19, 56);
  KF_RHOPI8(13, 8);
  KF_RHOPI8(12, 25);
  KF_RHOPI8(2, 43);
  KF_RHOPI8(20, 62);
  KF_RHOPI8(14, 18);
  KF_RHOPI8(22, 39);
  KF_RHOPI8(9, 61);
  KF_RHOPI8(6, 20);
  KF_RHOPI8(1, 44);
#undef KF_RHOPI8

#define KF_ROW(y)                                                              \
  do {                                                                         \
    __m512i r0 = v[(y)], r1 = v[(y) + 1], r2 = v[(y) + 2], r3 = v[(y) + 3],    \
            r4 = v[(y) + 4];                                                   \
    v[(y)]     = _mm512_ternarylogic_epi64(r0, r1, r2, 0xD2);                  \
    v[(y) + 1] = _mm512_ternarylogic_epi64(r1, r2, r3, 0xD2);                  \
    v[(y) + 2] = _mm512_ternarylogic_epi64(r2, r3, r4, 0xD2);                  \
    v[(y) + 3] = _mm512_ternarylogic_epi64(r3, r4, r0, 0xD2);                  \
    v[(y) + 4] = _mm512_ternarylogic_epi64(r4, r0, r1, 0xD2);                  \
  } while (0)
  KF_ROW(0);
  KF_ROW(5);
  KF_ROW(10);
  KF_ROW(15);
  KF_ROW(20);
#undef KF_ROW

  v[0] = _mm512_xor_si512(v[0], _mm512_set1_epi64((long long)rc));
}

__attribute__((target("avx512f")))
static void kf_permute_x8(uint64_t s[8][25]) {
  __m512i  v[25];
  uint64_t tmp[8];

  for (int j = 0; j < 25; j++) {
    for (int i = 0; i < 8; i++) tmp[i] = s[i][j];
    v[j] = _mm512_loadu_si512((const __m512i *)tmp);
  }
  for (int i = 0; i < 24; i++) kf_avx512_round_x8(v, RC[i]);
  for (int j = 0; j < 25; j++) {
    _mm512_storeu_si512((__m512i *)tmp, v[j]);
    for (int i = 0; i < 8; i++) s[i][j] = tmp[i];
  }
}

__attribute__((target("avx512f")))
static void kf_permute_x8_12(uint64_t s[8][25]) {
  __m512i  v[25];
  uint64_t tmp[8];

  for (int j = 0; j < 25; j++) {
    for (int i = 0; i < 8; i++) tmp[i] = s[i][j];
    v[j] = _mm512_loadu_si512((const __m512i *)tmp);
  }
  for (int i = 12; i < 24; i++) kf_avx512_round_x8(v, RC[i]);
  for (int j = 0; j < 25; j++) {
    _mm512_storeu_si512((__m512i *)tmp, v[j]);
    for (int i = 0; i < 8; i++) s[i][j] = tmp[i];
  }
}

__attribute__((target("avx512f")))
void kf_avx512_batch(uint64_t states[][25], size_t count) {
  size_t i = 0;
  for (; i + 8 <= count; i += 8) {
    kf_permute_x8(&states[i]);
  }
  for (; i < count; i++) {
    kf_scalar_permute(states[i]);
  }
}

__attribute__((target("avx512f")))
void kf_avx512_batch12(uint64_t states[][25], size_t count) {
  size_t i = 0;
  for (; i + 8 <= count; i += 8) {
    kf_permute_x8_12(&states[i]);
  }
  if (i < count) kf_scalar_batch12(&states[i], count - i);
}

__attribute__((constructor)) static void kf_avx512_register(void) {
  if (!__builtin_cpu_supports("avx512f")) {
    return;
  }
  if (kf_batch_priority <= KF_PRIO_AVX512) {
    kf_batch_perm     = kf_avx512_batch;
    kf_batch_perm12   = kf_avx512_batch12;
    kf_batch_priority = KF_PRIO_AVX512;
    kf_batch_lanes    = 8;
    kf_batch_label    = "avx512";
  }
}

#endif
