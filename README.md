# keccak-fast

Drop-in-speed replacement for `coruus/keccak-tiny`. Six SHA-3/SHAKE one-shots
plus batch entry points. Plain C11, libc only, no build flags,
runtime-dispatched, thread-safe.

## Use

```c
#include <finwo/keccak-fast.h>

kf_shake256(out, sizeof out, in, inlen);            /* 0, or -1 */
kf_shake256_batch(count, in, inlen, out, outlen);   /* equal-length, packed */
```

The one-shots (`kf_shake128`, `kf_shake256`, `kf_sha3_224`, `kf_sha3_256`,
`kf_sha3_384`, `kf_sha3_512`) are `kf_hash_fn` table entries: a call is one
indirect jump. Batch variants are `kf_<algo>_batch`, taking `count`
equal-length messages packed back to back.

## Build

```
dep add finwo/keccak-fast
```

`export.mk` lists the sources; `.dep.export` installs `<finwo/keccak-fast.h>`.

## Backends

| backend | one-shot | batch |
| ------- | -------- | ----- |
| scalar  | yes      | —     |
| AVX2    | no       | x4    |

Backends register from constructors; the highest available priority wins
(scalar 0, avx2 20, avx512 30). `kf_backend_name()` and `kf_batch_name()`
report the active ones. `KECCAK_FAST_NO_AVX2` drops the AVX2 backend.

The scalar backend is the donor, pinned to the x86-64 baseline
(`no-avx,no-avx2,no-avx512f`) so a consumer's `-march=native` cannot vectorize
it (clang runs 1.9x slower when it does).

## Dev

```
make test    # KAT and batch differential (TAP)
make bench   # vendored donor, pinned core, best-of-nine ns/hash
```

`bench/` fetches the donor via `dep install`. `OPT=-O2|-O3` (arch flags
rejected), `BENCH_CPU=<n>` selects the core.

## License

See `LICENSE.md`. The scalar backend is derived from `coruus/keccak-tiny`
(David Leon Gil, CC0).

