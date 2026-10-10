#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "keccak-fast.h"

int kct_sha3_256(uint8_t *, size_t, const uint8_t *, size_t);
int kct_shake256(uint8_t *, size_t, const uint8_t *, size_t);

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
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  return sched_setaffinity(0, sizeof set, &set);
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

static void run_pair(const char *name, kf_fn donor, kf_fn fast, size_t inlen,
                     size_t outlen, uint8_t *in, uint8_t *out, int reps,
                     uint64_t target_ns) {
  size_t iters = pick_iters(donor, out, outlen, in, inlen, target_ns);
  double bt = -1.0;
  double bf = -1.0;
  for (int r = 0; r < reps; r++) {
    double t = time_once(donor, out, outlen, in, inlen, iters);
    double f = time_once(fast, out, outlen, in, inlen, iters);
    if (bt < 0.0 || t < bt) bt = t;
    if (bf < 0.0 || f < bf) bf = f;
  }
  printf("%s\n", name);
  printf("  %-8s %9.2f ns/hash %9.3f Mh/s\n", "donor", bt, 1000.0 / bt);
  printf("  %-8s %9.2f ns/hash %9.3f Mh/s\n", kf_backend_name(), bf,
         1000.0 / bf);
  printf("  %-8s %9.3fx\n\n", "fast/do", bf / bt);
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

static void case_batch(const char *name, kf_batch_fn fn, size_t count,
                       size_t inlen, size_t outlen, uint8_t *in, uint8_t *out,
                       int reps, uint64_t target_ns) {
  double per = time_batch(fn, count, in, inlen, out, outlen, 200);
  if (per <= 0.0) per = 1.0;
  size_t iters = (size_t)((double)target_ns / (per * (double)count));
  if (iters < 10) iters = 10;

  double best = -1.0;
  for (int r = 0; r < reps; r++) {
    double v = time_batch(fn, count, in, inlen, out, outlen, iters);
    if (best < 0.0 || v < best) best = v;
  }
  char label[64];
  snprintf(label, sizeof label, "%s count %zu", name, count);
  printf("%-24s %9.2f ns/hash %9.3f Mh/s\n", label, best, 1000.0 / best);
}

int main(void) {
  const int      reps      = 9;
  const uint64_t target_ns = 25ULL * 1000000ULL;
  uint8_t        in[256];
  static uint8_t out[4096];
  int            cpu = 0;
  const char    *cs  = getenv("BENCH_CPU");

  for (size_t i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 31 + 7);
  if (cs) cpu = atoi(cs);

  printf("keccak-fast vs coruus/keccak-tiny\n");
  printf("build: %s\n", BENCH_FLAGS);
  if (pin_cpu(cpu) != 0) {
    printf("# warning: could not pin to cpu %d, results will be noisier\n", cpu);
  } else {
    printf("pinned to cpu %d\n", cpu);
  }
  printf("best of %d interleaved reps, about %llu ms per rep\n\n", reps,
         (unsigned long long)(target_ns / 1000000ULL));

  run_pair("SHA3-256 32->32", kct_sha3_256, kf_sha3_256, 32, 32, in, out, reps,
           target_ns);
  run_pair("SHA3-256 64->32", kct_sha3_256, kf_sha3_256, 64, 32, in, out, reps,
           target_ns);
  run_pair("SHAKE256 32->32", kct_shake256, kf_shake256, 32, 32, in, out, reps,
           target_ns);
  run_pair("SHAKE256 32->1088", kct_shake256, kf_shake256, 32, 1088, in, out, reps,
           target_ns);

  static uint8_t bin[256 * 64];
  static uint8_t bout[256 * 64];
  for (size_t i = 0; i < sizeof bin; i++) bin[i] = (uint8_t)(i * 17 + 3);

  printf("batch SHAKE256 32->32, per hash (%s)\n", kf_batch_name());
  case_batch(kf_batch_name(), kf_shake256_batch, 8, 32, 32, bin, bout, reps,
             target_ns);
  case_batch(kf_batch_name(), kf_shake256_batch, 64, 32, 32, bin, bout, reps,
             target_ns);
  case_batch(kf_batch_name(), kf_shake256_batch, 256, 32, 32, bin, bout, reps,
             target_ns);

  printf("batch SHA3-256 32->32, per hash (%s)\n", kf_batch_name());
  case_batch(kf_batch_name(), kf_sha3_256_batch, 8, 32, 32, bin, bout, reps,
             target_ns);
  case_batch(kf_batch_name(), kf_sha3_256_batch, 64, 32, 32, bin, bout, reps,
             target_ns);
  case_batch(kf_batch_name(), kf_sha3_256_batch, 256, 32, 32, bin, bout, reps,
             target_ns);

  printf("sink %llu\n", (unsigned long long)g_sink);
  return 0;
}
