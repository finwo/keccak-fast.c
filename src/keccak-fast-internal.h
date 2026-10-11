#ifndef FINWO_KECCAK_FAST_INTERNAL_H
#define FINWO_KECCAK_FAST_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "keccak-fast.h"

typedef void (*kf_batch_perm_fn)(uint64_t states[][25], size_t count);

extern kf_batch_perm_fn kf_batch_perm;
extern kf_batch_perm_fn kf_batch_perm12;
extern int              kf_batch_priority;
extern int              kf_batch_lanes;

extern int         kf_backend_priority;
extern const char *kf_backend_label;
extern const char *kf_batch_label;

#endif
