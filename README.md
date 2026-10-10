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
`kf_sha3_384`, `kf_sha3_512`, `kf_turboshake128`, `kf_turboshake256`) are
`kf_hash_fn` table entries: a call is one indirect jump. Batch variants are
`kf_<algo>_batch`, taking `count` equal-length messages packed back to back.
TurboSHAKE is the same sponge over Keccak-p[1600,12] with domain `0x1F`, about
1.9x faster than SHAKE; its batch entries use a separately registered 12-round
permutation.

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

The scalar backend is pinned to the x86-64 baseline
(`no-avx,no-avx2,no-avx512f,no-bmi,no-bmi2`) so a consumer's `-march=native`
cannot vectorize it or emit BMI. Its permutation keeps the 25 lanes in named
locals, fuses theta into the previous round's chi, and unrolls the round loop
4x; that beats both no unroll and a full 24x unroll. `scalar+bmi` is the same
permutation with `bmi` enabled, which turns chi's `not`+`and` into `andn`; gcc
also gets `rorx` for the rotates. About 20% faster than the donor.

The AVX2 and AVX-512 batch kernels hold the 4 or 8 messages of a group one per
vector lane, so the 25 state words live in 25 vector registers. The state is
transposed in 8x8 (or 4x4) blocks with unpack and shuffle instructions at the
sponge boundary. Their round bodies unroll theta and chi by hand so `-O2` emits
the same code as `-O3`.

## Dev

```
make test    # KAT and batch differential (TAP)
make bench   # per-hash table: scalar, scalar+bmi, avx2, avx512 (+ donor)
```

`bench/` fetches the donor via `dep install`. `OPT=-O2|-O3` (arch flags
rejected), `BENCH_CPU=<n>` selects the core.

## License

See `LICENSE.md`. The sponge is derived from `coruus/keccak-tiny` (David Leon
Gil, CC0); the scalar permutation follows XKCP's public-domain `opt64`
structure.

