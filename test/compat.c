#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "keccak-fast-compat.h"

static unsigned test_no;
static unsigned fails;

static void check(const char *what, int (*fn)(uint8_t *, size_t,
                                              const uint8_t *, size_t),
                  const uint8_t *in, size_t inlen, const char *hex) {
  uint8_t got[64];
  uint8_t want[64];
  size_t  outlen = strlen(hex) / 2;
  int     ok;

  for (size_t i = 0; i < outlen; i++) {
    unsigned v = 0;
    sscanf(hex + i * 2, "%2x", &v);
    want[i] = (uint8_t)v;
  }
  memset(got, 0, sizeof got);
  ok = fn(got, outlen, in, inlen) == 0 && memcmp(got, want, outlen) == 0;

  test_no++;
  printf("%s %u - %s\n", ok ? "ok" : "not ok", test_no, what);
  if (!ok) fails++;
}

int main(void) {
  const uint8_t *abc = (const uint8_t *)"abc";

  printf("TAP version 13\n");
  printf("# keccak-tiny compatibility\n");

  check("shake128 abc", shake128, abc, 3,
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
  check("shake256 abc", shake256, abc, 3,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");
  check("sha3_224 abc", sha3_224, abc, 3,
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
  check("sha3_256 abc", sha3_256, abc, 3,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  check("sha3_384 abc", sha3_384, abc, 3,
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
        "98d88cea927ac7f539f1edf228376d25");
  check("sha3_512 abc", sha3_512, abc, 3,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

  printf("1..%u\n", test_no);
  if (fails) printf("# %u of %u assertions failed\n", fails, test_no);
  return fails != 0;
}
