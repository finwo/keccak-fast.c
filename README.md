# keccak-fast

Drop-in-speed replacement for `coruus/keccak-tiny`. SHA-3/SHAKE one-shots,
TurboSHAKE128/256, and batch entry points. Plain C11, libc only, no build
flags, runtime-dispatched, thread-safe.

## Use

```c
#include <finwo/keccak-fast.h>

kf_shake256(out, sizeof out, in, inlen);            /* 0, or -1 */
kf_shake256_batch(count, in, inlen, out, outlen);   /* equal-length, packed */
```

The one-shots (`kf_shake128`, `kf_shake256`, `kf_sha3_224`, `kf_sha3_256`,
`kf_sha3_384`, `kf_sha3_512`) are `kf_hash_fn` table entries: a call is one
indirect jump. Batch variants are `kf_<algo>_batch`, taking `count`
equal-length messages packed back to back. `kf_turboshake128` and
`kf_turboshake256` implement TurboSHAKE (same sponge over Keccak-p[1600,12],
domain `0x1F`), about 1.9x faster than SHAKE.

## Build

```
dep add finwo/keccak-fast
```

`export.mk` lists the sources; `.dep.export` installs `<finwo/keccak-fast.h>`.

## Backends

| backend    | one-shot | batch |
| ---------- | -------- | ----- |
| scalar     | yes      | —     |
| scalar+bmi | yes      | —     |
| AVX2       | no       | x4    |
| AVX-512    | no       | x8    |

Backends register from constructors; the highest available priority wins
(scalar 0, scalar+bmi 10, avx2 20, avx512 30). `kf_backend_name()` and
`kf_batch_name()` report the active ones. `KECCAK_FAST_NO_BMI`,
`KECCAK_FAST_NO_AVX2` and `KECCAK_FAST_NO_AVX512` drop those backends.

The scalar backend is the donor, pinned to the x86-64 baseline
(`no-avx,no-avx2,no-avx512f,no-bmi,no-bmi2`) so a consumer's `-march=native`
cannot vectorize it or emit BMI. `scalar+bmi` is the same permutation with
`bmi` enabled, which turns chi's `not`+`and` into `andn`; gcc also gets `rorx`
for the rotates. About 11% faster than the donor.

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

