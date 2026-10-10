#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "keccak-fast.h"

typedef int (*kf_fn)(uint8_t *, size_t, const uint8_t *, size_t);
typedef int (*kf_batch_fn)(size_t, const uint8_t *, size_t, uint8_t *, size_t);

static int fails;
static int testn;

static void check(const char *name, int ok) {
  testn++;
  if (ok) {
    printf("ok %d - %s\n", testn, name);
  } else {
    fails++;
    printf("not ok %d - %s\n", testn, name);
  }
}

struct algo {
  const char  *name;
  kf_fn        one;
  kf_batch_fn  batch;
  size_t       outlen;
};

int main(void) {
  const struct algo algos[] = {
    {"shake128", kf_shake128, kf_shake128_batch, 32},
    {"shake256", kf_shake256, kf_shake256_batch, 64},
    {"sha3_224", kf_sha3_224, kf_sha3_224_batch, 28},
    {"sha3_256", kf_sha3_256, kf_sha3_256_batch, 32},
    {"sha3_384", kf_sha3_384, kf_sha3_384_batch, 48},
    {"sha3_512", kf_sha3_512, kf_sha3_512_batch, 64},
  };
  static const size_t counts[] = {1, 3, 4, 5, 8, 17};
  static const size_t inlens[] = {32, 200};
  static uint8_t      in[17 * 200];
  static uint8_t      want[17 * 64];
  static uint8_t      got[17 * 64];

  printf("1..%zu\n", (sizeof algos / sizeof algos[0]) *
                       (sizeof counts / sizeof counts[0]) *
                       (sizeof inlens / sizeof inlens[0]));

  for (size_t a = 0; a < sizeof algos / sizeof algos[0]; a++) {
    for (size_t ci = 0; ci < sizeof counts / sizeof counts[0]; ci++) {
      size_t count = counts[ci];
      for (size_t li = 0; li < sizeof inlens / sizeof inlens[0]; li++) {
        size_t inlen  = inlens[li];
        size_t outlen = algos[a].outlen;
        char   name[64];

        for (size_t m = 0; m < count; m++) {
          for (size_t j = 0; j < inlen; j++) {
            in[m * inlen + j] = (uint8_t)(j * 31 + m * 7 + 1);
          }
        }
        for (size_t m = 0; m < count; m++) {
          int rc = algos[a].one(want + m * outlen, outlen, in + m * inlen,
                                inlen);
          if (rc != 0) {
            printf("# %s one-shot returned %d\n", algos[a].name, rc);
          }
        }

        memset(got, 0, count * outlen);
        int rc = algos[a].batch(count, in, inlen, got, outlen);
        snprintf(name, sizeof name, "%s count=%zu inlen=%zu", algos[a].name,
                 count, inlen);
        check(name, rc == 0 && memcmp(want, got, count * outlen) == 0);
      }
    }
  }

  printf("# batch backend: %s\n", kf_batch_name());

  if (fails != 0) printf("# %d failed\n", fails);
  return fails != 0;
}
