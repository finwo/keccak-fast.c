#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "keccak-fast.h"

typedef int (*kf_fn)(uint8_t *, size_t, const uint8_t *, size_t);

int kf_scalar_shake128(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_shake256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_sha3_224(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_sha3_256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_sha3_384(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_sha3_512(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_turboshake128(uint8_t *, size_t, const uint8_t *, size_t);
int kf_scalar_turboshake256(uint8_t *, size_t, const uint8_t *, size_t);

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_BMI)
int kf_bmi_shake128(uint8_t *, size_t, const uint8_t *, size_t);
int kf_bmi_shake256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_bmi_sha3_224(uint8_t *, size_t, const uint8_t *, size_t);
int kf_bmi_sha3_256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_bmi_sha3_384(uint8_t *, size_t, const uint8_t *, size_t);
int kf_bmi_sha3_512(uint8_t *, size_t, const uint8_t *, size_t);
int kf_bmi_turboshake128(uint8_t *, size_t, const uint8_t *, size_t);
int kf_bmi_turboshake256(uint8_t *, size_t, const uint8_t *, size_t);
#endif

#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)
int kf_armsha3_available(void);
int kf_armsha3_shake128(uint8_t *, size_t, const uint8_t *, size_t);
int kf_armsha3_shake256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_armsha3_sha3_224(uint8_t *, size_t, const uint8_t *, size_t);
int kf_armsha3_sha3_256(uint8_t *, size_t, const uint8_t *, size_t);
int kf_armsha3_sha3_384(uint8_t *, size_t, const uint8_t *, size_t);
int kf_armsha3_sha3_512(uint8_t *, size_t, const uint8_t *, size_t);
int kf_armsha3_turboshake128(uint8_t *, size_t, const uint8_t *, size_t);
int kf_armsha3_turboshake256(uint8_t *, size_t, const uint8_t *, size_t);
#endif

typedef struct {
  const char *label;
  kf_fn       shake128;
  kf_fn       shake256;
  kf_fn       sha3_224;
  kf_fn       sha3_256;
  kf_fn       sha3_384;
  kf_fn       sha3_512;
  kf_fn       turboshake128;
  kf_fn       turboshake256;
} backend;

static int fails;
static int testn;

static void hex2bin(const char *hex, uint8_t *out) {
  for (size_t i = 0; hex[i] != '\0'; i += 2) {
    unsigned v;
    sscanf(hex + i, "%2x", &v);
    out[i / 2] = (uint8_t)v;
  }
}

static void check(const char *be, const char *name, kf_fn fn,
                  const uint8_t *in, size_t inlen, const char *hex) {
  uint8_t got[64] = {0};
  uint8_t want[64] = {0};
  size_t  outlen  = strlen(hex) / 2;
  int     rc      = fn(got, outlen, in, inlen);
  hex2bin(hex, want);
  testn++;
  if (rc == 0 && memcmp(got, want, outlen) == 0) {
    printf("ok %d - %s %s\n", testn, be, name);
  } else {
    fails++;
    printf("not ok %d - %s %s\n", testn, be, name);
  }
}

static void run(const backend *b, const uint8_t *qbf) {
  const uint8_t *abc = (const uint8_t *)"abc";
  const uint8_t *nil = NULL;

  check(b->label, "shake128 empty", b->shake128, nil, 0,
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
  check(b->label, "shake128 abc", b->shake128, abc, 3,
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
  check(b->label, "shake256 empty", b->shake256, nil, 0,
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
  check(b->label, "shake256 abc", b->shake256, abc, 3,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");

  check(b->label, "sha3_224 empty", b->sha3_224, nil, 0,
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
  check(b->label, "sha3_224 abc", b->sha3_224, abc, 3,
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
  check(b->label, "sha3_256 empty", b->sha3_256, nil, 0,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
  check(b->label, "sha3_256 abc", b->sha3_256, abc, 3,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  check(b->label, "sha3_256 200", b->sha3_256, qbf, 200,
        "5f728f63bf5ee48c77f453c0490398fa645b8d4c4e56be9a41cfec344d6ca899");
  check(b->label, "sha3_384 empty", b->sha3_384, nil, 0,
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
        "c3713831264adb47fb6bd1e058d5f004");
  check(b->label, "sha3_384 abc", b->sha3_384, abc, 3,
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
        "98d88cea927ac7f539f1edf228376d25");
  check(b->label, "sha3_512 empty", b->sha3_512, nil, 0,
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
  check(b->label, "sha3_512 abc", b->sha3_512, abc, 3,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

  check(b->label, "turboshake128 empty", b->turboshake128, nil, 0,
        "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c");
  check(b->label, "turboshake128 abc", b->turboshake128, abc, 3,
        "dcf1646dfe993a8eb6b782d1faaca6d82416a5dcf1de98ee3c6dbc5e1dc63018");
  check(b->label, "turboshake128 200", b->turboshake128, qbf, 200,
        "5b96f9aac16a9047cd03b83c950fb6b074a31ea05f0aaa3aa3a7f98deaab289c");
  check(b->label, "turboshake256 empty", b->turboshake256, nil, 0,
        "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db"
        "11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0");
  check(b->label, "turboshake256 abc", b->turboshake256, abc, 3,
        "63824b1431a7372e85edc022c9d7afdd027472fcfa33c887d6f5aaf8dc5d4db6"
        "8afbcb5714b49b7ffd8dd115dd5bd5436f837236845a230d6969a4083a113617");
  check(b->label, "turboshake256 200", b->turboshake256, qbf, 200,
        "c27b5422da9177efaf2a335b6ea79cb57961a8cc3ca8f870f17ebbbfd662086a"
        "fe62a10085fb7c413fcc0f586aa938d152254a77aa0d682eb846c82199428a71");

  uint8_t out[64];
  int     bad1 = b->sha3_256(out, 33, abc, 3);
  int     bad2 = b->sha3_256(NULL, 32, abc, 3);
  int     bad3 = b->shake256(out, 32, NULL, 3);
  printf("%s %d - %s sha3_256 rejects long output\n",
         bad1 == -1 ? "ok" : "not ok", ++testn, b->label);
  printf("%s %d - %s rejects NULL output\n", bad2 == -1 ? "ok" : "not ok",
         ++testn, b->label);
  printf("%s %d - %s rejects NULL input\n", bad3 == -1 ? "ok" : "not ok",
         ++testn, b->label);
  if (bad1 != -1 || bad2 != -1 || bad3 != -1) fails++;
}

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_BMI)
static int have_bmi(void) {
#if defined(__clang__)
  return __builtin_cpu_supports("bmi");
#else
  return __builtin_cpu_supports("bmi") && __builtin_cpu_supports("bmi2");
#endif
}
#endif

int main(void) {
  static uint8_t qbf[200];
  backend        bes[4];
  int            nb = 0;

  for (size_t i = 0; i < sizeof qbf; i++) qbf[i] = (uint8_t)i;

  bes[nb++] = (backend){"dispatch", kf_shake128, kf_shake256,
                        kf_sha3_224, kf_sha3_256, kf_sha3_384, kf_sha3_512,
                        kf_turboshake128, kf_turboshake256};
  bes[nb++] = (backend){"scalar", kf_scalar_shake128, kf_scalar_shake256,
                        kf_scalar_sha3_224, kf_scalar_sha3_256,
                        kf_scalar_sha3_384, kf_scalar_sha3_512,
                        kf_scalar_turboshake128, kf_scalar_turboshake256};
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__)) && \
    !defined(KECCAK_FAST_NO_BMI)
  if (have_bmi())
    bes[nb++] = (backend){"scalar+bmi", kf_bmi_shake128, kf_bmi_shake256,
                          kf_bmi_sha3_224, kf_bmi_sha3_256, kf_bmi_sha3_384,
                          kf_bmi_sha3_512, kf_bmi_turboshake128,
                          kf_bmi_turboshake256};
#endif
#if defined(__aarch64__) && !defined(KECCAK_FAST_NO_SHA3)
  if (kf_armsha3_available())
    bes[nb++] = (backend){"arm-sha3", kf_armsha3_shake128,
                          kf_armsha3_shake256, kf_armsha3_sha3_224,
                          kf_armsha3_sha3_256, kf_armsha3_sha3_384,
                          kf_armsha3_sha3_512, kf_armsha3_turboshake128,
                          kf_armsha3_turboshake256};
#endif

  printf("1..%d\n", 22 * nb);
  for (int i = 0; i < nb; i++) run(&bes[i], qbf);

  printf("# dispatched backend: %s\n", kf_backend_name());

  if (fails != 0) printf("# %d failed\n", fails);
  return fails != 0;
}
