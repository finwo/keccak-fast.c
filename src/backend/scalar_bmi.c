/* Runtime BMI1/BMI2 variant of the scalar backend. Same source as scalar.c,
 * but the target enables `andn` (replaces `not`+`and` in chi) and `rorx`. */

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

#define KF_PREFIX kf_bmi_
#define KF_LINKAGE static
#include "scalar-impl.h"

static void kf_bmi_batch(uint64_t states[][25], size_t count) {
  for (size_t i = 0; i < count; i++) {
    keccakf(states[i]);
  }
}

__attribute__((constructor)) static void kf_bmi_register(void) {
#if defined(__clang__)
  if (!__builtin_cpu_supports("bmi")) {
#else
  if (!__builtin_cpu_supports("bmi") || !__builtin_cpu_supports("bmi2")) {
#endif
    return;
  }
  if (kf_backend_priority <= KF_PRIO_BMI) {
    kf_shake128 = kf_bmi_shake128;
    kf_shake256 = kf_bmi_shake256;
    kf_sha3_224 = kf_bmi_sha3_224;
    kf_sha3_256 = kf_bmi_sha3_256;
    kf_sha3_384 = kf_bmi_sha3_384;
    kf_sha3_512 = kf_bmi_sha3_512;
    kf_backend_priority = KF_PRIO_BMI;
    kf_backend_label    = "scalar+bmi";
  }
  if (kf_batch_priority <= KF_PRIO_BMI) {
    kf_batch_perm     = kf_bmi_batch;
    kf_batch_priority = KF_PRIO_BMI;
    kf_batch_lanes    = 1;
    kf_batch_label    = "scalar+bmi";
  }
}

#if defined(__clang__)
#pragma clang attribute pop
#endif

#endif
