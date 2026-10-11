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
int kf_scalar_shake256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_turboshake256(uint8_t *, size_t, const uint8_t *, size_t);

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_AVX2)
void kf_avx2_batch(uint64_t states[][25], size_t count);
void kf_avx2_batch12(uint64_t states[][25], size_t count);
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_AVX512)
void kf_avx512_batch(uint64_t states[][25], size_t count);
void kf_avx512_batch12(uint64_t states[][25], size_t count);
#endif
#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)
int  kf_armsha3_available(void);
void kf_armsha3_batch(uint64_t states[][25], size_t count);
void kf_armsha3_batch12(uint64_t states[][25], size_t count);
#endif

#ifndef BENCH_FLAGS
#define BENCH_FLAGS ""
#endif

typedef int (*kf_fn)(uint8_t *, size_t, const uint8_t *, size_t);
typedef int (*kf_batch_fn)(size_t, const uint8_t *, size_t, uint8_t *, size_t);

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

static size_t pick_iters(kf_fn fn, uint8_t *out, size_t outlen,
                         const uint8_t *in, size_t inlen, uint64_t target_ns) {
  double per = time_once(fn, out, outlen, in, inlen, 1000);
  if (per <= 0.0) per = 1.0;
  size_t iters = (size_t)((double)target_ns / per);
  return iters < 100 ? 100 : iters;
}

typedef struct {
  const char *label;
  kf_fn       fn;
} oneshot_t;

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

typedef struct {
  const char      *label;
  kf_batch_perm_fn perm;
  kf_batch_perm_fn perm12;
  int              lanes;
} batch_t;

static void case_all(const char *title, const oneshot_t *os, int nos,
                     const batch_t *bs, int nbs, kf_fn donor,
                     kf_batch_fn batch_fn, size_t count, size_t inlen,
                     size_t outlen, uint8_t *in, uint8_t *out, int reps,
                     uint64_t target_ns) {
  double bd = -1.0, bos[4], bbs[4];
  kf_fn  iters_fn = donor ? donor : os[0].fn;
  size_t iters = pick_iters(iters_fn, out, outlen, in, inlen, target_ns);
  for (int i = 0; i < nos; i++) bos[i] = -1.0;
  for (int i = 0; i < nbs; i++) bbs[i] = -1.0;

  size_t biters = 0;
  if (nbs > 0) {
    kf_batch_perm   = bs[0].perm;
    kf_batch_perm12 = bs[0].perm12;
    kf_batch_lanes  = bs[0].lanes;
    double per = time_batch(batch_fn, count, in, inlen, out, outlen, 200);
    if (per <= 0.0) per = 1.0;
    biters = (size_t)((double)target_ns / (per * (double)count));
    if (biters < 10) biters = 10;
  }

  kf_batch_perm_fn saved_perm   = kf_batch_perm;
  kf_batch_perm_fn saved_perm12 = kf_batch_perm12;
  int              saved_lanes  = kf_batch_lanes;

  for (int r = 0; r < reps; r++) {
    if (donor != NULL) {
      double d = time_once(donor, out, outlen, in, inlen, iters);
      if (bd < 0.0 || d < bd) bd = d;
    }
    for (int i = 0; i < nos; i++) {
      double v = time_once(os[i].fn, out, outlen, in, inlen, iters);
      if (bos[i] < 0.0 || v < bos[i]) bos[i] = v;
    }
    for (int i = 0; i < nbs; i++) {
      kf_batch_perm   = bs[i].perm;
      kf_batch_perm12 = bs[i].perm12;
      kf_batch_lanes  = bs[i].lanes;
      double v = time_batch(batch_fn, count, in, inlen, out, outlen, biters);
      if (bbs[i] < 0.0 || v < bbs[i]) bbs[i] = v;
    }
  }

  kf_batch_perm   = saved_perm;
  kf_batch_perm12 = saved_perm12;
  kf_batch_lanes  = saved_lanes;

  printf("%s\n", title);
  if (donor != NULL) {
    printf("  %-12s %9.2f ns/hash %9.3f Mh/s\n", "donor", bd, 1000.0 / bd);
  }
  for (int i = 0; i < nos; i++)
    printf("  %-12s %9.2f ns/hash %9.3f Mh/s\n", os[i].label, bos[i],
           1000.0 / bos[i]);
  for (int i = 0; i < nbs; i++)
    printf("  %-12s %9.2f ns/hash %9.3f Mh/s\n", bs[i].label, bbs[i],
           1000.0 / bbs[i]);
  printf("\n");
}

int main(void) {
  const int      reps      = 9;
  const uint64_t target_ns = 25ULL * 1000000ULL;
  static uint8_t in[64 * 1088];
  static uint8_t out[64 * 1088];
  int            cpu = 0;
  const char    *cs  = getenv("BENCH_CPU");

  for (size_t i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 31 + 7);
  if (cs) cpu = atoi(cs);

  printf("keccak-fast backend comparison\n");
  printf("build: %s\n", BENCH_FLAGS);
  if (pin_cpu(cpu) != 0) {
    printf("# warning: could not pin to cpu %d, results will be noisier\n", cpu);
  } else {
    printf("pinned to cpu %d\n", cpu);
  }
  printf("best of %d interleaved reps, about %llu ms per rep\n\n", reps,
         (unsigned long long)(target_ns / 1000000ULL));

  const oneshot_t sha3[] = {
      {"scalar", kf_scalar_sha3_256},
      {kf_backend_name(), kf_sha3_256},
  };
  const oneshot_t shake[] = {
      {"scalar", kf_scalar_shake256},
      {kf_backend_name(), kf_shake256},
  };
  const oneshot_t ts256[] = {
      {"scalar", kf_scalar_turboshake256},
      {kf_backend_name(), kf_turboshake256},
  };

  batch_t batch[4];
  int     nb = 0;
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_AVX2)
  if (__builtin_cpu_supports("avx2"))
    batch[nb++] = (batch_t){"avx2 x4", kf_avx2_batch, kf_avx2_batch12, 4};
#endif
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_AVX512)
  if (__builtin_cpu_supports("avx512f"))
    batch[nb++] = (batch_t){"avx512 x8", kf_avx512_batch, kf_avx512_batch12, 8};
#endif
#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)
  if (kf_armsha3_available())
    batch[nb++] = (batch_t){"arm-sha3 x2", kf_armsha3_batch, kf_armsha3_batch12, 2};
#endif

  case_all("SHA3-256 32->32, per hash", sha3, 2, batch, nb, kct_sha3_256,
           kf_sha3_256_batch, 64, 32, 32, in, out, reps, target_ns);
  case_all("SHA3-256 64->32, per hash", sha3, 2, batch, nb, kct_sha3_256,
           kf_sha3_256_batch, 64, 64, 32, in, out, reps, target_ns);
  case_all("SHAKE256 32->32, per hash", shake, 2, batch, nb, kct_shake256,
           kf_shake256_batch, 64, 32, 32, in, out, reps, target_ns);
  case_all("SHAKE256 32->1088, per hash", shake, 2, batch, nb, kct_shake256,
           kf_shake256_batch, 64, 32, 1088, in, out, reps, target_ns);
  case_all("TurboSHAKE256 32->32, per hash", ts256, 2, batch, nb, NULL,
           kf_turboshake256_batch, 64, 32, 32, in, out, reps, target_ns);

  printf("sink %llu\n", (unsigned long long)g_sink);
  return 0;
}
