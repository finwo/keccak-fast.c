#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#include "../keccak-fast-internal.h"

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_AVX2)

static const uint64_t RC[24] = {
  1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
  0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
  0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
  0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

#define KF_ROL64(x, n) \
  _mm256_or_si256(_mm256_slli_epi64((x), (n)), _mm256_srli_epi64((x), 64 - (n)))

__attribute__((target("avx2")))
static inline void kf_avx2_round_x4(__m256i v[25], uint64_t rc) {
  __m256i c[5];
  __m256i d[5];
  __m256i t, u;

  for (int x = 0; x < 5; x++) {
    c[x] = _mm256_xor_si256(
      _mm256_xor_si256(v[x], v[x + 5]),
      _mm256_xor_si256(_mm256_xor_si256(v[x + 10], v[x + 15]), v[x + 20]));
  }
  for (int x = 0; x < 5; x++) {
    d[x] = _mm256_xor_si256(c[(x + 4) % 5], KF_ROL64(c[(x + 1) % 5], 1));
  }
  for (int y = 0; y < 5; y++) {
    for (int x = 0; x < 5; x++) {
      v[x + 5 * y] = _mm256_xor_si256(v[x + 5 * y], d[x]);
    }
  }

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

  for (int y = 0; y < 5; y++) {
    __m256i row[5];
    for (int x = 0; x < 5; x++) row[x] = v[x + 5 * y];
    for (int x = 0; x < 5; x++) {
      v[x + 5 * y] = _mm256_xor_si256(
        row[x], _mm256_andnot_si256(row[(x + 1) % 5], row[(x + 2) % 5]));
    }
  }

  v[0] = _mm256_xor_si256(v[0], _mm256_set1_epi64x((long long)rc));
}

__attribute__((target("avx2")))
static void kf_permute_x4(uint64_t s[4][25]) {
  __m256i  v[25];
  uint64_t tmp[4];

  for (int j = 0; j < 25; j++) {
    for (int i = 0; i < 4; i++) tmp[i] = s[i][j];
    v[j] = _mm256_loadu_si256((const __m256i *)tmp);
  }
  for (int i = 0; i < 24; i++) kf_avx2_round_x4(v, RC[i]);
  for (int j = 0; j < 25; j++) {
    _mm256_storeu_si256((__m256i *)tmp, v[j]);
    for (int i = 0; i < 4; i++) s[i][j] = tmp[i];
  }
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
