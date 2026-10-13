# keccak-fast

Drop-in-speed replacement for `coruus/keccak-tiny`. SHA-3/SHAKE one-shots,
TurboSHAKE128/256, batch entry points and fused iterated chains. Plain C11,
libc only, no build flags, runtime-dispatched, thread-safe.

## Use

```c
#include <finwo/keccak-fast.h>

kf_shake256(out, sizeof out, in, inlen);            /* 0, or -1 */
kf_shake256_batch(count, in, inlen, out, outlen);   /* equal-length, packed */
kf_shake256_chain(count, x, 32, tail, 8, 1, 0, 256);
```

`<algo>`: `shake128`, `shake256`, `sha3_224`, `sha3_256`, `sha3_384`,
`sha3_512`, `turboshake128`, `turboshake256`.

- `kf_<algo>`: one-shot, a `kf_hash_fn` pointer, so a call is one indirect jump
- `kf_<algo>_batch`: `count` equal-length messages, packed back to back
- `kf_<algo>_chain`: iterated, see below

TurboSHAKE is the same sponge over Keccak-p[1600,12] with domain `0x1F`, about
1.9x SHAKE, on a separately registered 12-round permutation.

## Chains

`kf_<algo>_chain` iterates a hash into itself, `count` chains at a time:

```
x_r = H(x_r || tail_r || ctr)      repeated `iters` times
```

- `tail_r`: `tail_len` caller-defined bytes, constant across iterations, packed
  back to back like the batch inputs
- `ctr`: `ctr_len` bytes (0 or 1) from `ctr0`, incremented each iteration
- returns `-1` unless `outlen + tail_len + ctr_len <= rate - 1`, i.e. one
  permutation per iteration

Covers plain iterated hashing, counter-only chains, tweaked chains, and both at
once. No wider counter: forces an endianness choice into every kernel, and
composes anyway by calling again with an updated tail.

Tightest fit is SHA3-512: rate 72, 7 bytes beside the digest.

Vector backends hold state in registers across iterations, `_batch` loop would
pay transpose + scalar absorb per step.

## Replacing keccak-tiny

```c
#include <finwo/keccak-fast-compat.h>   /* was <coruus/keccak-tiny.h> */
```

Maps the six `keccak-tiny` names onto their `kf_` equivalents, claims
`KECCAK_FIPS202_H` so either include order works. Signatures are identical.

Not carried over: `&sha3_256` and friends, the `kf_` names are dispatch
pointers, not functions.

## Build

```
dep add finwo/keccak-fast
```

`export.mk` lists the sources, `.dep.export` installs `<finwo/keccak-fast.h>`
and `<finwo/keccak-fast-compat.h>`.

## Backends

Lanes and priority per track:

| backend    | one-shot | batch   | chain         |
| ---------- | -------- | ------- | ------------- |
| scalar     | 100      | x1, 100 | x1, 100       |
| scalar+bmi | 115      | x1, 114 | x1, 114       |
| arm-sha3   | 101      | x2, 182 | x2, 194       |
| AVX2       | -        | x4, 218 | x4 fused, 265 |
| AVX-512    | -        | x8, 447 | x8 fused, 786 |

Backends register from constructors, highest available priority wins. Priority
is measured, not ranked: scalar is 100, the rest are throughput relative to it
on the same track (265 = 2.65x scalar). One-shot scored on absorb MiB/s, batch
and chain on hashes per second, from `make bench` at SHA3-256. An x1 batch has
no vector kernel and falls through to the one-shot loop.

Numbers vary by core, so they encode ordering, not a promise. `arm-sha3` is the
one to watch: scalar parity for one-shot on a Cortex-A72, ~1.4x on Apple
silicon. Re-run `make bench` on a new target before trusting that ordering.

`kf_backend_name()`, `kf_batch_name()` and `kf_chain_name()` report the active
backends. `KECCAK_FAST_NO_BMI`, `KECCAK_FAST_NO_AVX2`, `KECCAK_FAST_NO_AVX512`
and `KECCAK_FAST_NO_SHA3` drop those backends.

- `scalar`: pinned to cpu baseline (no extensions:
  `no-avx,no-avx2,no-avx512f,no-bmi,no-bmi2`), so a consumer's `-march=native`
  cannot vectorize it or emit BMI. 25 lanes in named locals, theta fused into
  the previous round's chi, round loop unrolled 4x (beats no unroll and 24x).
- `scalar+bmi`: same permutation with `bmi`, turning chi's `not`+`and` into
  `andn`, gcc also gets `rorx` for the rotates. ~20% over the donor.
- `arm-sha3`: ARMv8.2 `eor3`, `bcax`, `rax1`, `xar` under a scoped
  `target("sha3")` region, no build flags. Self-contained: own permutation and
  sponge, 25 lanes in named locals so they stay in NEON registers. Runtime
  availability only (`hw.optional.arm.FEAT_SHA3` on Darwin, `HWCAP_SHA3` on
  Linux). x2 kernels pack two messages per 128-bit register, ~2x scalar.
- `AVX2`, `AVX-512`: 4 or 8 messages one per lane, 25 state words in 25 vector
  registers, transposed in 4x4 or 8x8 blocks at the sponge boundary. Theta and
  chi unrolled by hand, so `-O2` emits what `-O3` does.

Chain kernels transpose on entry and exit only, rebuilding the message in the
transposed domain between permutations. A digest length not a multiple of 8
leaves one straddling word, masked rather than copied. `scalar`, `scalar+bmi`
and `arm-sha3` rebuild the block in memory instead: batching, no register
residency.

## Dev

```
make test    # KAT, batch, chain and compat differentials (TAP)
make bench   # per-algo table: every backend, every mode, plus the donor
```

`bench/` fetches the donor via `dep install`. `OPT=-O2|-O3` (arch flags
rejected), `BENCH_CPU=<n>` selects the core.

## License

See `LICENSE.md`. The sponge is derived from `coruus/keccak-tiny` (David Leon
Gil, CC0); the scalar permutation follows XKCP's public-domain `opt64`
structure. The `arm-sha3` permutation is an independent implementation over
the ARMv8.2 SHA3 instructions.

