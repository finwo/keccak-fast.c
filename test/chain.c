#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keccak-fast-internal.h"
#include "keccak-fast.h"

#define KF_CHAIN_PROTO(name)                                                   \
  void name(size_t, uint8_t *, size_t, const uint8_t *, size_t, size_t,        \
            uint8_t, uint32_t, size_t, uint8_t)

KF_CHAIN_PROTO(kf_scalar_chain);
KF_CHAIN_PROTO(kf_scalar_chain12);

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_BMI)
KF_CHAIN_PROTO(kf_bmi_chain);
KF_CHAIN_PROTO(kf_bmi_chain12);
#endif

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_AVX2)
KF_CHAIN_PROTO(kf_avx2_chain);
KF_CHAIN_PROTO(kf_avx2_chain12);
#endif

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_AVX512)
KF_CHAIN_PROTO(kf_avx512_chain);
KF_CHAIN_PROTO(kf_avx512_chain12);
#endif

#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_ARM_SHA3)
int kf_armsha3_available(void);
KF_CHAIN_PROTO(kf_armsha3_chain);
KF_CHAIN_PROTO(kf_armsha3_chain12);
#endif

typedef int (*chain_fn)(size_t, uint8_t *, size_t, const uint8_t *, size_t,
                        size_t, uint8_t, uint32_t);

typedef struct {
  const char *name;
  kf_hash_fn *one;
  chain_fn    chain;
  size_t      rate;
  size_t      outlen;
} algo;

typedef struct {
  const char *label;
  kf_chain_fn kernel;
  kf_chain_fn kernel12;
  int         lanes;
} kernel_row;

static unsigned test_no;
static unsigned fails;

static void check(const char *what, int ok) {
  test_no++;
  printf("%s %u - %s\n", ok ? "ok" : "not ok", test_no, what);
  if (!ok) fails++;
}

static int ref_chain(kf_hash_fn one, uint8_t *x, size_t count, size_t outlen,
                     const uint8_t *tail, size_t tail_len, size_t ctr_len,
                     uint8_t ctr0, uint32_t iters) {
  uint8_t blk[200];
  for (size_t r = 0; r < count; r++) {
    uint8_t *xr = x + r * outlen;
    for (uint32_t it = 0; it < iters; it++) {
      memcpy(blk, xr, outlen);
      if (tail_len) memcpy(blk + outlen, tail + r * tail_len, tail_len);
      if (ctr_len) blk[outlen + tail_len] = (uint8_t)(ctr0 + it);
      if (one(xr, outlen, blk, outlen + tail_len + ctr_len) != 0) return -1;
    }
  }
  return 0;
}

static void fill(uint8_t *p, size_t n, unsigned seed) {
  for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(i * 31 + seed * 7 + 1);
}

int main(void) {
  const algo algos[] = {
    {"shake128", &kf_shake128, kf_shake128_chain, 168, 32},
    {"shake256", &kf_shake256, kf_shake256_chain, 136, 32},
    {"sha3_224", &kf_sha3_224, kf_sha3_224_chain, 144, 28},
    {"sha3_256", &kf_sha3_256, kf_sha3_256_chain, 136, 32},
    {"sha3_384", &kf_sha3_384, kf_sha3_384_chain, 104, 48},
    {"sha3_512", &kf_sha3_512, kf_sha3_512_chain, 72, 64},
    {"turboshake128", &kf_turboshake128, kf_turboshake128_chain, 168, 32},
    {"turboshake256", &kf_turboshake256, kf_turboshake256_chain, 136, 32},
  };
  const uint32_t iters_set[] = {0, 1, 255, 256};
  const size_t   nalgo       = sizeof algos / sizeof algos[0];

  kernel_row kernels[4];
  int        nk = 0;

  kernels[nk++] =
      (kernel_row){"scalar x1", kf_scalar_chain, kf_scalar_chain12, 1};
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_BMI)
#if defined(__clang__)
  if (__builtin_cpu_supports("bmi"))
#else
  if (__builtin_cpu_supports("bmi") && __builtin_cpu_supports("bmi2"))
#endif
    kernels[nk++] = (kernel_row){"bmi x1", kf_bmi_chain, kf_bmi_chain12, 1};
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_AVX2)
  if (__builtin_cpu_supports("avx2"))
    kernels[nk++] = (kernel_row){"avx2 x4", kf_avx2_chain, kf_avx2_chain12, 4};
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
  !defined(KECCAK_FAST_NO_AVX512)
  if (__builtin_cpu_supports("avx512f"))
    kernels[nk++] =
        (kernel_row){"avx512 x8", kf_avx512_chain, kf_avx512_chain12, 8};
#endif
#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_ARM_SHA3)
  if (kf_armsha3_available())
    kernels[nk++] =
        (kernel_row){"arm-sha3 x2", kf_armsha3_chain, kf_armsha3_chain12, 2};
#endif

  uint8_t *xa = malloc(1000 * 64);
  uint8_t *xb = malloc(1000 * 64);
  uint8_t *tl = malloc(1000 * 200);
  if (!xa || !xb || !tl) return 1;

  printf("TAP version 13\n");
  printf("# fused iterated sponge\n");

  for (int k = 0; k < nk; k++) {
    kf_chain_kernel   = kernels[k].kernel;
    kf_chain_kernel12 = kernels[k].kernel12;
    kf_chain_lanes    = kernels[k].lanes;

    size_t L      = (size_t)kernels[k].lanes;
    size_t cnt[5] = {1, L > 1 ? L - 1 : 1, L, L + 1, 17};

    for (size_t a = 0; a < nalgo; a++) {
      size_t outlen = algos[a].outlen;
      for (size_t ctr_len = 0; ctr_len <= 1; ctr_len++) {
        size_t tmax = algos[a].rate - 1 - outlen - ctr_len;
        size_t tls[2] = {0, tmax};
        for (int t = 0; t < 2; t++) {
          size_t tail_len = tls[t];
          for (int c = 0; c < 5; c++) {
            size_t count = cnt[c];
            for (int w = 0; w < 4; w++) {
              uint32_t iters = iters_set[w];
              char     name[128];

              fill(xa, count * outlen, 3);
              memcpy(xb, xa, count * outlen);
              if (tail_len) fill(tl, count * tail_len, 9);

              int rc1 = ref_chain(*algos[a].one, xa, count, outlen, tl,
                                  tail_len, ctr_len, 0x5a, iters);
              int rc2 = algos[a].chain(count, xb, outlen, tl, tail_len,
                                       ctr_len, 0x5a, iters);

              snprintf(name, sizeof name,
                       "%s %s count=%zu iters=%u tail=%zu ctr=%zu",
                       kernels[k].label, algos[a].name, count, iters, tail_len,
                       ctr_len);
              check(name, rc1 == 0 && rc2 == 0 &&
                              memcmp(xa, xb, count * outlen) == 0);
            }
          }

          fill(xa, 1000 * outlen, 4);
          memcpy(xb, xa, 1000 * outlen);
          if (tail_len) fill(tl, 1000 * tail_len, 11);
          char big[128];
          int  r1 = ref_chain(*algos[a].one, xa, 1000, outlen, tl, tail_len,
                              ctr_len, 0x11, 2);
          int  r2 = algos[a].chain(1000, xb, outlen, tl, tail_len, ctr_len,
                                   0x11, 2);
          snprintf(big, sizeof big, "%s %s count=1000 iters=2 tail=%zu ctr=%zu",
                   kernels[k].label, algos[a].name, tail_len, ctr_len);
          check(big, r1 == 0 && r2 == 0 &&
                         memcmp(xa, xb, 1000 * outlen) == 0);
        }
      }
    }
  }

  check("rejects outlen 0", kf_sha3_256_chain(1, xa, 0, NULL, 0, 0, 0, 1) == -1);
  check("rejects ctr_len 2",
        kf_sha3_256_chain(1, xa, 32, NULL, 0, 2, 0, 1) == -1);
  check("rejects oversized block",
        kf_sha3_512_chain(1, xa, 64, tl, 7, 1, 0, 1) == -1);
  check("rejects null x", kf_sha3_256_chain(1, NULL, 32, NULL, 0, 0, 0, 1) == -1);
  check("rejects null tail with len",
        kf_sha3_256_chain(1, xa, 32, NULL, 8, 0, 0, 1) == -1);
  check("accepts exact block fit",
        kf_sha3_512_chain(1, xa, 64, tl, 6, 1, 0, 1) == 0);

  free(xa);
  free(xb);
  free(tl);

  printf("1..%u\n", test_no);
  if (fails) printf("# %u of %u assertions failed\n", fails, test_no);
  printf("# chain backend: %s\n", kf_chain_name());
  return fails != 0;
}
