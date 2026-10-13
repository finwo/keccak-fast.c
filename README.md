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

The one-shots (`kf_shake128`, `kf_shake256`, `kf_sha3_224`, `kf_sha3_256`,
`kf_sha3_384`, `kf_sha3_512`, `kf_turboshake128`, `kf_turboshake256`) are
`kf_hash_fn` table entries: a call is one indirect jump. Batch variants are
`kf_<algo>_batch`, taking `count` equal-length messages packed back to back.
TurboSHAKE is the same sponge over Keccak-p[1600,12] with domain `0x1F`, about
1.9x faster than SHAKE; its batch entries use a separately registered 12-round
permutation.

## Chains

`kf_<algo>_chain` iterates a hash into itself, `count` chains at a time:

```
x_r = H(x_r || tail_r || ctr)      repeated `iters` times
```

`tail_r` is `tail_len` caller-defined bytes, constant across iterations and
packed back to back like the batch inputs. `ctr` is `ctr_len` bytes, 0 or 1,
starting at `ctr0` and incremented every iteration, so all four of plain
iterated hashing, counter-only chains, tweaked chains and both together are
expressible. A wider counter is deliberately not offered: it would force an
endianness choice into every kernel, and the construction composes by calling
again with an updated tail.

Each iteration must be a single permutation, so `outlen + tail_len + ctr_len`
has to fit in `rate - 1`; anything larger returns `-1`. At the tight end that
is SHA3-512, where `rate` is 72 and a 64-byte digest leaves 7 bytes.

The win is that the vector backends keep the state in registers across
iterations. The batch entry points only expose a permutation, so a feedback
loop built on them pays a full transpose and a scalar byte-wise absorb per
step; the chain kernels rewrite only the words below the digest and permute
again. `kf_chain_name()` reports the active kernel, which is tracked and
dispatched separately from the batch one.

## Build

```
dep add finwo/keccak-fast
```

`export.mk` lists the sources; `.dep.export` installs `<finwo/keccak-fast.h>`.

## Backends

| backend    | one-shot | batch | chain    |
| ---------- | -------- | ----- | -------- |
| scalar     | yes      | -     | x1       |
| scalar+bmi | yes      | -     | x1       |
| arm-sha3   | yes      | x2    | x2       |
| AVX2       | no       | x4    | x4 fused |
| AVX-512    | no       | x8    | x8 fused |

Backends register from constructors and the highest available priority wins.
Priority is measured, not ranked: scalar is 100 and every other number is that
backend's throughput relative to scalar on the same track, so 265 means 2.65x
scalar. One-shot is scored on absorb MiB/s, batch and chain on hashes per
second, both from `make bench` at SHA3-256.

| backend    | one-shot | batch | chain |
| ---------- | -------- | ----- | ----- |
| scalar     | 100      | 100   | 100   |
| scalar+bmi | 115      | 114   | 114   |
| arm-sha3   | 101      | 182   | 194   |
| AVX2       | -        | 218   | 265   |
| AVX-512    | -        | 447   | 786   |

These are a fixed approximation of a quantity that varies by core, so they
encode the ordering rather than a promise. `arm-sha3` is the one to watch: it
measures at parity with scalar for one-shot on a Cortex-A72 and about 1.4x on
Apple silicon, so 101 is conservative and the pair kernels carry its win.
Re-run `make bench` on a new target before trusting the one-shot ordering
there. `kf_backend_name()`, `kf_batch_name()` and `kf_chain_name()` report the
active ones. `KECCAK_FAST_NO_BMI`,
`KECCAK_FAST_NO_AVX2`, `KECCAK_FAST_NO_AVX512` and `KECCAK_FAST_NO_SHA3` drop
those backends.

The scalar backend is pinned to the x86-64 baseline
(`no-avx,no-avx2,no-avx512f,no-bmi,no-bmi2`) so a consumer's `-march=native`
cannot vectorize it or emit BMI. Its permutation keeps the 25 lanes in named
locals, fuses theta into the previous round's chi, and unrolls the round loop
4x; that beats both no unroll and a full 24x unroll. `scalar+bmi` is the same
permutation with `bmi` enabled, which turns chi's `not`+`and` into `andn`; gcc
also gets `rorx` for the rotates. About 20% faster than the donor.

`arm-sha3` uses the ARMv8.2 SHA3 instructions (`eor3`, `bcax`, `rax1`, `xar`)
under a scoped `target("sha3")` region, so no build flags are needed. It is
self-contained: its own permutation and sponge, nothing shared with the scalar
backend, and its 25 lanes live in named locals so the register allocator keeps
them in NEON registers. Availability is checked at runtime only
(`hw.optional.arm.FEAT_SHA3` on Darwin, `HWCAP_SHA3` on Linux); the x2 batch
kernel packs two messages one per 64-bit half of each 128-bit register. About
1.4x scalar for one-shots on Apple silicon and ~2x for the x2 batch; on some
cores the one-shot lands at parity and the pair kernel carries the win.

The AVX2 and AVX-512 batch kernels hold the 4 or 8 messages of a group one per
vector lane, so the 25 state words live in 25 vector registers. The state is
transposed in 8x8 (or 4x4) blocks with unpack and shuffle instructions at the
sponge boundary. Their round bodies unroll theta and chi by hand so `-O2` emits
the same code as `-O3`. Their chain kernels transpose once on entry and once on
exit rather than per iteration, rebuilding the message in the transposed domain
between permutations; a digest whose length is not a multiple of 8 leaves one
word straddling the boundary, which is masked rather than copied. The scalar,
`scalar+bmi` and `arm-sha3` chain kernels reuse their own permutations and
rebuild the block in memory, so they gain correctness and batching but not the
register residency.

## Dev

```
make test    # KAT, batch and chain differentials (TAP)
make bench   # per-hash table: every backend, plus the donor
```

`bench/` fetches the donor via `dep install`. `OPT=-O2|-O3` (arch flags
rejected), `BENCH_CPU=<n>` selects the core.

## License

See `LICENSE.md`. The sponge is derived from `coruus/keccak-tiny` (David Leon
Gil, CC0); the scalar permutation follows XKCP's public-domain `opt64`
structure. The `arm-sha3` permutation is an independent implementation over
the ARMv8.2 SHA3 instructions.

