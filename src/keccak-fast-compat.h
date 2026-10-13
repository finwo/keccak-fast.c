#ifndef FINWO_KECCAK_FAST_COMPAT_H
#define FINWO_KECCAK_FAST_COMPAT_H

/* Claims keccak-tiny's include guard, so either order of inclusion works */
#ifndef KECCAK_FIPS202_H
#define KECCAK_FIPS202_H
#endif

#include "keccak-fast.h"

#define shake128 kf_shake128
#define shake256 kf_shake256
#define sha3_224 kf_sha3_224
#define sha3_256 kf_sha3_256
#define sha3_384 kf_sha3_384
#define sha3_512 kf_sha3_512

#endif
