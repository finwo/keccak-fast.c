#if defined(__linux__)
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "keccak-fast.h"
#include "keccak-fast-internal.h"

int kct_sha3_256(uint8_t *, size_t, const uint8_t *, size_t);
int kct_shake256(uint8_t *, size_t, const uint8_t *, size_t);

int kf_scalar_sha3_256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_sha3_512(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_shake128(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_shake256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_turboshake128(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_turboshake256(uint8_t *, size_t, const uint8_t *, size_t);

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
void kf_avx2_batch(uint64_t states[][25], size_t count);
void kf_avx2_batch12(uint64_t states[][25], size_t count);
void kf_avx2_chain(size_t, uint8_t *, size_t, const uint8_t *, size_t, size_t,
                   uint8_t, uint32_t, size_t, uint8_t);
void kf_avx2_chain12(size_t, uint8_t *, size_t, const uint8_t *, size_t, size_t,
                     uint8_t, uint32_t, size_t, uint8_t);
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_AVX512)
void kf_avx512_batch(uint64_t states[][25], size_t count);
void kf_avx512_batch12(uint64_t states[][25], size_t count);
void kf_avx512_chain(size_t, uint8_t *, size_t, const uint8_t *, size_t, size_t,
                     uint8_t, uint32_t, size_t, uint8_t);
void kf_avx512_chain12(size_t, uint8_t *, size_t, const uint8_t *, size_t,
                       size_t, uint8_t, uint32_t, size_t, uint8_t);
#endif
#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)
int  kf_armsha3_available(void);
void kf_armsha3_batch(uint64_t states[][25], size_t count);
void kf_armsha3_batch12(uint64_t states[][25], size_t count);
void kf_armsha3_chain(size_t, uint8_t *, size_t, const uint8_t *, size_t,
                      size_t, uint8_t, uint32_t, size_t, uint8_t);
void kf_armsha3_chain12(size_t, uint8_t *, size_t, const uint8_t *, size_t,
                        size_t, uint8_t, uint32_t, size_t, uint8_t);
#endif

#ifndef BENCH_FLAGS
#define BENCH_FLAGS ""
#endif

#define BENCH_COUNT  64
#define BENCH_LINKS  256
#define BENCH_STREAM 16384

typedef int (*kf_fn)(uint8_t *, size_t, const uint8_t *, size_t);
typedef int (*kf_batch_fn)(size_t, const uint8_t *, size_t, uint8_t *, size_t);
typedef int (*kf_chain_api)(size_t, uint8_t *, size_t, const uint8_t *, size_t,
                            size_t, uint8_t, uint32_t);

static volatile uint64_t g_sink;

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int pin_cpu(int cpu) {
#if defined(__linux__)
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  return sched_setaffinity(0, sizeof set, &set);
#else
  (void)cpu;
  return -1;
#endif
}

static double time_once(kf_fn fn, uint8_t *out, size_t outlen,
                        const uint8_t *in, size_t inlen, size_t iters) {
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fn(out, outlen, in, inlen);
    g_sink += out[0];
  }
  return (double)(now_ns() - t0) / (double)iters;
}

static double time_batch(kf_batch_fn fn, size_t count, const uint8_t *in,
                         size_t inlen, uint8_t *out, size_t outlen,
                         size_t iters) {
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fn(count, in, inlen, out, outlen);
    g_sink += out[0];
  }
  return (double)(now_ns() - t0) / ((double)iters * (double)count);
}

static double time_chain(kf_chain_api fn, size_t count, uint8_t *x,
                         size_t outlen, const uint8_t *tail, size_t tail_len,
                         size_t ctr_len, size_t iters) {
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fn(count, x, outlen, tail, tail_len, ctr_len, 0, BENCH_LINKS);
    g_sink += x[0];
  }
  return (double)(now_ns() - t0) /
         ((double)iters * (double)count * (double)BENCH_LINKS);
}

enum { ONE_NONE = 0, ONE_SCALAR, ONE_DISPATCH, ONE_DONOR };

typedef struct {
  const char      *label;
  int              one;
  kf_batch_perm_fn perm;
  kf_batch_perm_fn perm12;
  kf_chain_fn      chain;
  kf_chain_fn      chain12;
  int              lanes;
} row_t;

typedef struct {
  const char  *name;
  size_t       rate;
  kf_fn        donor;
  kf_fn        scalar_one;
  kf_hash_fn  *dispatched;
  kf_batch_fn  batch_fn;
  kf_chain_api chain_fn;
  size_t       inlen;
  size_t       outlen;
  size_t       tail_len;
  size_t       ctr_len;
  int          xof;
} algo_t;

static void cell(double v) {
  if (v < 0.0) {
    printf(" %10s", "-");
  } else {
    printf(" %10.3f", v);
  }
}

static double best_once(kf_fn fn, uint8_t *out, size_t outlen,
                        const uint8_t *in, size_t inlen, int reps,
                        uint64_t target_ns) {
  double probe = time_once(fn, out, outlen, in, inlen, 20);
  if (probe <= 0.0) probe = 1.0;
  size_t iters = (size_t)((double)target_ns / probe);
  if (iters < 5) iters = 5;
  double best = -1.0;
  for (int k = 0; k < reps; k++) {
    double t = time_once(fn, out, outlen, in, inlen, iters);
    if (best < 0.0 || t < best) best = t;
  }
  return best;
}

static double mibs(double ns) {
  return (double)BENCH_STREAM * 1e9 / (ns * 1048576.0);
}

static void report_algo(const algo_t *a, const row_t *rows, int nrows,
                        uint8_t *in, uint8_t *out, int reps,
                        uint64_t target_ns) {
  kf_batch_perm_fn sp   = kf_batch_perm;
  kf_batch_perm_fn sp12 = kf_batch_perm12;
  int              sl   = kf_batch_lanes;
  kf_chain_fn      sc   = kf_chain_kernel;
  kf_chain_fn      sc12 = kf_chain_kernel12;
  int              scl  = kf_chain_lanes;

  printf("%s, rate %zu, %zu byte block\n", a->name, a->rate, a->inlen);
  printf("  %-12s %10s %10s %10s %10s %10s\n", "backend", "one-shot", "batch",
         "chain", "absorb", "squeeze");
  printf("  %-12s %10s %10s %10s %10s %10s\n", "", "Mh/s", "Mh/s", "Mh/s",
         "MiB/s", "MiB/s");

  for (int i = 0; i < nrows; i++) {
    const row_t *r     = &rows[i];
    kf_fn        one   = NULL;
    double       v_one = -1.0, v_bat = -1.0, v_chn = -1.0;
    double       v_abs = -1.0, v_sqz = -1.0;

    if (r->one == ONE_SCALAR) one = a->scalar_one;
    if (r->one == ONE_DISPATCH) one = *a->dispatched;
    if (r->one == ONE_DONOR) one = a->donor;
    if (r->one == ONE_DONOR && a->donor == NULL) continue;

    if (one != NULL) {
      v_one = 1000.0 / best_once(one, out, a->outlen, in, a->inlen, reps,
                                 target_ns);
      v_abs = mibs(best_once(one, out, a->outlen, in, BENCH_STREAM, reps,
                             target_ns));
      if (a->xof) {
        v_sqz = mibs(
            best_once(one, out, BENCH_STREAM, in, 32, reps, target_ns));
      }
    }

    if (r->perm != NULL) {
      kf_batch_perm   = r->perm;
      kf_batch_perm12 = r->perm12;
      kf_batch_lanes  = r->lanes;
      double p = time_batch(a->batch_fn, BENCH_COUNT, in, a->inlen, out,
                            a->outlen, 200);
      if (p <= 0.0) p = 1.0;
      size_t it = (size_t)((double)target_ns / (p * (double)BENCH_COUNT));
      if (it < 10) it = 10;
      double best = -1.0;
      for (int k = 0; k < reps; k++) {
        double t = time_batch(a->batch_fn, BENCH_COUNT, in, a->inlen, out,
                              a->outlen, it);
        if (best < 0.0 || t < best) best = t;
      }
      v_bat = 1000.0 / best;
    }

    if (r->chain != NULL && a->chain_fn != NULL) {
      kf_chain_kernel   = r->chain;
      kf_chain_kernel12 = r->chain12;
      kf_chain_lanes    = r->lanes;
      double p = time_chain(a->chain_fn, BENCH_COUNT, out, a->outlen, in,
                            a->tail_len, a->ctr_len, 2);
      if (p <= 0.0) p = 1.0;
      size_t it = (size_t)((double)target_ns /
                           (p * (double)BENCH_COUNT * (double)BENCH_LINKS));
      if (it < 2) it = 2;
      double best = -1.0;
      for (int k = 0; k < reps; k++) {
        double t = time_chain(a->chain_fn, BENCH_COUNT, out, a->outlen, in,
                              a->tail_len, a->ctr_len, it);
        if (best < 0.0 || t < best) best = t;
      }
      v_chn = 1000.0 / best;
    }

    printf("  %-12s", r->label);
    cell(v_one);
    cell(v_bat);
    cell(v_chn);
    cell(v_abs);
    cell(v_sqz);
    printf("\n");
  }

  kf_batch_perm     = sp;
  kf_batch_perm12   = sp12;
  kf_batch_lanes    = sl;
  kf_chain_kernel   = sc;
  kf_chain_kernel12 = sc12;
  kf_chain_lanes    = scl;
  printf("\n");
}

static void explain(void) {
  printf("One table per algorithm, one row per backend. Higher is better in\n");
  printf("every column. A dash means the backend has no kernel for that mode.\n\n");
  printf("  one-shot  1 hash per call, time / calls\n");
  printf("              kf_sha3_256(out, 32, in, inlen)\n");
  printf("  batch     %d messages per call, time / (calls * %d)\n", BENCH_COUNT,
         BENCH_COUNT);
  printf("              kf_sha3_256_batch(%d, in, inlen, out, 32)\n",
         BENCH_COUNT);
  printf("  chain     %d chains advanced %d links per call,\n", BENCH_COUNT,
         BENCH_LINKS);
  printf("            time / (calls * %d * %d)\n", BENCH_COUNT, BENCH_LINKS);
  printf("              kf_sha3_256_chain(%d, x, 32, tail, t, 1, 0, %d)\n",
         BENCH_COUNT, BENCH_LINKS);
  printf("\n");
  printf("Each table fixes the hashed block, so all three modes run the same\n");
  printf("number of permutations per hash and the spread across them is\n");
  printf("per-call overhead alone. The chain tail is sized so its block\n");
  printf("matches the one-shot input length.\n\n");
  printf("The last two columns move %d KiB on a single stream instead, and\n",
         BENCH_STREAM / 1024);
  printf("are one-shot only. Batch and chain exist to step a whole group, so\n");
  printf("the question they answer is hashes per second, not bytes per second\n");
  printf("down one stream.\n\n");
  printf("  absorb    long input, short digest. What a checksum over a file\n");
  printf("            sees, and the number that matters for plain SHA3.\n");
  printf("  squeeze   short input, long output. The sponge is seeded once and\n");
  printf("            then stepped, which is what an XOF is for and the number\n");
  printf("            that matters for the SHAKE variants.\n\n");
  printf("Both directions cost rate bytes per permutation, so rate is the\n");
  printf("ceiling and the tables are ordered by it.\n");
  printf("\n");
}

int main(void) {
  const int      reps      = 9;
  const uint64_t target_ns = 25ULL * 1000000ULL;
  const size_t   in_cap  = BENCH_COUNT * BENCH_STREAM;
  const size_t   out_cap = BENCH_COUNT * BENCH_STREAM;
  uint8_t       *in      = malloc(in_cap);
  uint8_t       *out     = malloc(out_cap);
  int            cpu     = 0;
  const char    *cs      = getenv("BENCH_CPU");

  if (in == NULL || out == NULL) return 1;
  for (size_t i = 0; i < in_cap; i++) in[i] = (uint8_t)(i * 31 + 7);
  if (cs) cpu = atoi(cs);

  printf("keccak-fast backend comparison\n");
  printf("build: %s\n", BENCH_FLAGS);
  if (pin_cpu(cpu) != 0) {
    printf("# warning: could not pin to cpu %d, results will be noisier\n", cpu);
  } else {
    printf("pinned to cpu %d\n", cpu);
  }
  printf("best of %d interleaved reps, about %llu ms per rep\n", reps,
         (unsigned long long)(target_ns / 1000000ULL));
  printf("dispatched: core %s, batch %s, chain %s\n\n", kf_backend_name(),
         kf_batch_name(), kf_chain_name());
  explain();

  row_t rows[6];
  int   nr = 0;

  rows[nr++] = (row_t){"donor", ONE_DONOR, NULL, NULL, NULL, NULL, 1};
  rows[nr++] = (row_t){"scalar",          ONE_SCALAR, NULL, NULL,
                       kf_scalar_chain,   kf_scalar_chain12, 1};
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_BMI)
#if defined(__clang__)
  if (__builtin_cpu_supports("bmi"))
#else
  if (__builtin_cpu_supports("bmi") && __builtin_cpu_supports("bmi2"))
#endif
    rows[nr++] = (row_t){kf_backend_name(), ONE_DISPATCH, NULL, NULL,
                         kf_bmi_chain,      kf_bmi_chain12, 1};
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_AVX2)
  if (__builtin_cpu_supports("avx2"))
    rows[nr++] = (row_t){"avx2 x4",       ONE_NONE,         kf_avx2_batch,
                         kf_avx2_batch12, kf_avx2_chain,    kf_avx2_chain12, 4};
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_AVX512)
  if (__builtin_cpu_supports("avx512f"))
    rows[nr++] =
        (row_t){"avx512 x8",       ONE_NONE,        kf_avx512_batch,
                kf_avx512_batch12, kf_avx512_chain, kf_avx512_chain12, 8};
#endif
#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)
  if (kf_armsha3_available())
    rows[nr++] =
        (row_t){"arm-sha3 x2",      ONE_DISPATCH,     kf_armsha3_batch,
                kf_armsha3_batch12, kf_armsha3_chain, kf_armsha3_chain12, 2};
#endif

  const algo_t algos[] = {
      {"SHAKE128", 168, NULL, kf_scalar_shake128, &kf_shake128,
       kf_shake128_batch, kf_shake128_chain, 64, 32, 31, 1, 1},
      {"TurboSHAKE128", 168, NULL, kf_scalar_turboshake128, &kf_turboshake128,
       kf_turboshake128_batch, kf_turboshake128_chain, 64, 32, 31, 1, 1},
      {"SHA3-256", 136, kct_sha3_256, kf_scalar_sha3_256, &kf_sha3_256,
       kf_sha3_256_batch, kf_sha3_256_chain, 64, 32, 31, 1, 0},
      {"SHAKE256", 136, kct_shake256, kf_scalar_shake256, &kf_shake256,
       kf_shake256_batch, kf_shake256_chain, 64, 32, 31, 1, 1},
      {"TurboSHAKE256", 136, NULL, kf_scalar_turboshake256, &kf_turboshake256,
       kf_turboshake256_batch, kf_turboshake256_chain, 64, 32, 31, 1, 1},
      {"SHA3-512", 72, NULL, kf_scalar_sha3_512, &kf_sha3_512,
       kf_sha3_512_batch, kf_sha3_512_chain, 64, 64, 6, 1, 0},
  };

  for (size_t i = 0; i < sizeof algos / sizeof algos[0]; i++) {
    report_algo(&algos[i], rows, nr, in, out, reps, target_ns);
  }

  printf("sink %llu\n", (unsigned long long)g_sink);
  free(in);
  free(out);
  return 0;
}
