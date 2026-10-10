/* Keccak-f[1600] and the FIPS 202 sponge of coruus/keccak-tiny, renamed
 * kf_scalar_* for the dispatcher.
 *
 * Implementor: David Leon Gil. License: CC0, attribution kindly requested.
 * Blame taken too, but not liability.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../keccak-fast-internal.h"

/* The fallback must run on any x86-64: no AVX (clang vectorizes it under
 * -march=native and runs 1.9x slower) and no BMI (that is scalar_bmi.c). */
#if defined(__clang__) && (defined(__x86_64__) || defined(__i386__))
#pragma clang attribute push(                                                  \
    __attribute__((target("no-avx,no-avx2,no-avx512f,no-bmi,no-bmi2"))),        \
    apply_to=function)
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#pragma GCC target("no-avx,no-avx2,no-avx512f,no-bmi,no-bmi2")
#endif

#define KF_PREFIX kf_scalar_
#define KF_LINKAGE
#include "scalar-impl.h"

void kf_scalar_permute(uint64_t state[25]) {
  keccakf(state);
}

void kf_scalar_batch(uint64_t states[][25], size_t count) {
  for (size_t i = 0; i < count; i++) {
    keccakf(states[i]);
  }
}

__attribute__((constructor)) static void kf_scalar_register(void) {
  if (kf_backend_priority <= KF_PRIO_SCALAR) {
    kf_shake128 = kf_scalar_shake128;
    kf_shake256 = kf_scalar_shake256;
    kf_sha3_224 = kf_scalar_sha3_224;
    kf_sha3_256 = kf_scalar_sha3_256;
    kf_sha3_384 = kf_scalar_sha3_384;
    kf_sha3_512 = kf_scalar_sha3_512;
    kf_turboshake128 = kf_scalar_turboshake128;
    kf_turboshake256 = kf_scalar_turboshake256;
    kf_backend_priority = KF_PRIO_SCALAR;
    kf_backend_label    = "scalar";
  }
  if (kf_batch_priority <= KF_PRIO_SCALAR) {
    kf_batch_perm     = kf_scalar_batch;
    kf_batch_priority = KF_PRIO_SCALAR;
    kf_batch_lanes    = 1;
    kf_batch_label    = "scalar";
  }
}

#if defined(__clang__) && (defined(__x86_64__) || defined(__i386__))
#pragma clang attribute pop
#endif
