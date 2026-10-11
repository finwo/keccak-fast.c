#ifndef FINWO_ARM_SHA3_PERM_H
#define FINWO_ARM_SHA3_PERM_H

/* Keccak-p[1600] using the ARMv8.2 SHA3 instructions (EOR3, BCAX, RAX1, XAR).
 *
 * The including translation unit must have <arm_neon.h> in scope, define
 * RC[24], and be compiled with the sha3 target enabled (arm_sha3.c does this
 * with a scoped target region). The 25 lanes live in named locals, not an
 * indexed array, so the register allocator keeps them in NEON registers (an
 * array gets spilled by gcc). Each 128-bit register holds one 64-bit lane in
 * its low half; the x2 entry points pack two independent states one per half.
 *
 * theta is fused into rho: XAR(t, D, 64 - rot) computes ROL(t ^ D, rot), so
 * each lane is theta-added and rho-rotated in a single instruction. */

#define KFA3_DECL(P)                                                          \
  uint64x2_t P##0, P##1, P##2, P##3, P##4, P##5, P##6, P##7, P##8, P##9,      \
      P##10, P##11, P##12, P##13, P##14, P##15, P##16, P##17, P##18, P##19,   \
      P##20, P##21, P##22, P##23, P##24

#define KFA3_LOAD1(P, S)                                                      \
  P##0  = vdupq_n_u64((S)[0]);                                                \
  P##1  = vdupq_n_u64((S)[1]);                                                \
  P##2  = vdupq_n_u64((S)[2]);                                                \
  P##3  = vdupq_n_u64((S)[3]);                                                \
  P##4  = vdupq_n_u64((S)[4]);                                                \
  P##5  = vdupq_n_u64((S)[5]);                                                \
  P##6  = vdupq_n_u64((S)[6]);                                                \
  P##7  = vdupq_n_u64((S)[7]);                                                \
  P##8  = vdupq_n_u64((S)[8]);                                                \
  P##9  = vdupq_n_u64((S)[9]);                                                \
  P##10 = vdupq_n_u64((S)[10]);                                               \
  P##11 = vdupq_n_u64((S)[11]);                                               \
  P##12 = vdupq_n_u64((S)[12]);                                               \
  P##13 = vdupq_n_u64((S)[13]);                                               \
  P##14 = vdupq_n_u64((S)[14]);                                               \
  P##15 = vdupq_n_u64((S)[15]);                                               \
  P##16 = vdupq_n_u64((S)[16]);                                               \
  P##17 = vdupq_n_u64((S)[17]);                                               \
  P##18 = vdupq_n_u64((S)[18]);                                               \
  P##19 = vdupq_n_u64((S)[19]);                                               \
  P##20 = vdupq_n_u64((S)[20]);                                               \
  P##21 = vdupq_n_u64((S)[21]);                                               \
  P##22 = vdupq_n_u64((S)[22]);                                               \
  P##23 = vdupq_n_u64((S)[23]);                                               \
  P##24 = vdupq_n_u64((S)[24]);

#define KFA3_STORE1(S, P)                                                     \
  (S)[0]  = vgetq_lane_u64(P##0, 0);                                          \
  (S)[1]  = vgetq_lane_u64(P##1, 0);                                          \
  (S)[2]  = vgetq_lane_u64(P##2, 0);                                          \
  (S)[3]  = vgetq_lane_u64(P##3, 0);                                          \
  (S)[4]  = vgetq_lane_u64(P##4, 0);                                          \
  (S)[5]  = vgetq_lane_u64(P##5, 0);                                          \
  (S)[6]  = vgetq_lane_u64(P##6, 0);                                          \
  (S)[7]  = vgetq_lane_u64(P##7, 0);                                          \
  (S)[8]  = vgetq_lane_u64(P##8, 0);                                          \
  (S)[9]  = vgetq_lane_u64(P##9, 0);                                          \
  (S)[10] = vgetq_lane_u64(P##10, 0);                                         \
  (S)[11] = vgetq_lane_u64(P##11, 0);                                         \
  (S)[12] = vgetq_lane_u64(P##12, 0);                                         \
  (S)[13] = vgetq_lane_u64(P##13, 0);                                         \
  (S)[14] = vgetq_lane_u64(P##14, 0);                                         \
  (S)[15] = vgetq_lane_u64(P##15, 0);                                         \
  (S)[16] = vgetq_lane_u64(P##16, 0);                                         \
  (S)[17] = vgetq_lane_u64(P##17, 0);                                         \
  (S)[18] = vgetq_lane_u64(P##18, 0);                                         \
  (S)[19] = vgetq_lane_u64(P##19, 0);                                         \
  (S)[20] = vgetq_lane_u64(P##20, 0);                                         \
  (S)[21] = vgetq_lane_u64(P##21, 0);                                         \
  (S)[22] = vgetq_lane_u64(P##22, 0);                                         \
  (S)[23] = vgetq_lane_u64(P##23, 0);                                         \
  (S)[24] = vgetq_lane_u64(P##24, 0);

#define KFA3_LOAD2(P, S)                                                      \
  P##0  = vcombine_u64(vcreate_u64((S)[0][0]), vcreate_u64((S)[1][0]));       \
  P##1  = vcombine_u64(vcreate_u64((S)[0][1]), vcreate_u64((S)[1][1]));       \
  P##2  = vcombine_u64(vcreate_u64((S)[0][2]), vcreate_u64((S)[1][2]));       \
  P##3  = vcombine_u64(vcreate_u64((S)[0][3]), vcreate_u64((S)[1][3]));       \
  P##4  = vcombine_u64(vcreate_u64((S)[0][4]), vcreate_u64((S)[1][4]));       \
  P##5  = vcombine_u64(vcreate_u64((S)[0][5]), vcreate_u64((S)[1][5]));       \
  P##6  = vcombine_u64(vcreate_u64((S)[0][6]), vcreate_u64((S)[1][6]));       \
  P##7  = vcombine_u64(vcreate_u64((S)[0][7]), vcreate_u64((S)[1][7]));       \
  P##8  = vcombine_u64(vcreate_u64((S)[0][8]), vcreate_u64((S)[1][8]));       \
  P##9  = vcombine_u64(vcreate_u64((S)[0][9]), vcreate_u64((S)[1][9]));       \
  P##10 = vcombine_u64(vcreate_u64((S)[0][10]), vcreate_u64((S)[1][10]));     \
  P##11 = vcombine_u64(vcreate_u64((S)[0][11]), vcreate_u64((S)[1][11]));     \
  P##12 = vcombine_u64(vcreate_u64((S)[0][12]), vcreate_u64((S)[1][12]));     \
  P##13 = vcombine_u64(vcreate_u64((S)[0][13]), vcreate_u64((S)[1][13]));     \
  P##14 = vcombine_u64(vcreate_u64((S)[0][14]), vcreate_u64((S)[1][14]));     \
  P##15 = vcombine_u64(vcreate_u64((S)[0][15]), vcreate_u64((S)[1][15]));     \
  P##16 = vcombine_u64(vcreate_u64((S)[0][16]), vcreate_u64((S)[1][16]));     \
  P##17 = vcombine_u64(vcreate_u64((S)[0][17]), vcreate_u64((S)[1][17]));     \
  P##18 = vcombine_u64(vcreate_u64((S)[0][18]), vcreate_u64((S)[1][18]));     \
  P##19 = vcombine_u64(vcreate_u64((S)[0][19]), vcreate_u64((S)[1][19]));     \
  P##20 = vcombine_u64(vcreate_u64((S)[0][20]), vcreate_u64((S)[1][20]));     \
  P##21 = vcombine_u64(vcreate_u64((S)[0][21]), vcreate_u64((S)[1][21]));     \
  P##22 = vcombine_u64(vcreate_u64((S)[0][22]), vcreate_u64((S)[1][22]));     \
  P##23 = vcombine_u64(vcreate_u64((S)[0][23]), vcreate_u64((S)[1][23]));     \
  P##24 = vcombine_u64(vcreate_u64((S)[0][24]), vcreate_u64((S)[1][24]));

#define KFA3_STORE2(S, P)                                                     \
  (S)[0][0]  = vgetq_lane_u64(P##0, 0);                                       \
  (S)[1][0]  = vgetq_lane_u64(P##0, 1);                                       \
  (S)[0][1]  = vgetq_lane_u64(P##1, 0);                                       \
  (S)[1][1]  = vgetq_lane_u64(P##1, 1);                                       \
  (S)[0][2]  = vgetq_lane_u64(P##2, 0);                                       \
  (S)[1][2]  = vgetq_lane_u64(P##2, 1);                                       \
  (S)[0][3]  = vgetq_lane_u64(P##3, 0);                                       \
  (S)[1][3]  = vgetq_lane_u64(P##3, 1);                                       \
  (S)[0][4]  = vgetq_lane_u64(P##4, 0);                                       \
  (S)[1][4]  = vgetq_lane_u64(P##4, 1);                                       \
  (S)[0][5]  = vgetq_lane_u64(P##5, 0);                                       \
  (S)[1][5]  = vgetq_lane_u64(P##5, 1);                                       \
  (S)[0][6]  = vgetq_lane_u64(P##6, 0);                                       \
  (S)[1][6]  = vgetq_lane_u64(P##6, 1);                                       \
  (S)[0][7]  = vgetq_lane_u64(P##7, 0);                                       \
  (S)[1][7]  = vgetq_lane_u64(P##7, 1);                                       \
  (S)[0][8]  = vgetq_lane_u64(P##8, 0);                                       \
  (S)[1][8]  = vgetq_lane_u64(P##8, 1);                                       \
  (S)[0][9]  = vgetq_lane_u64(P##9, 0);                                       \
  (S)[1][9]  = vgetq_lane_u64(P##9, 1);                                       \
  (S)[0][10] = vgetq_lane_u64(P##10, 0);                                      \
  (S)[1][10] = vgetq_lane_u64(P##10, 1);                                      \
  (S)[0][11] = vgetq_lane_u64(P##11, 0);                                      \
  (S)[1][11] = vgetq_lane_u64(P##11, 1);                                      \
  (S)[0][12] = vgetq_lane_u64(P##12, 0);                                      \
  (S)[1][12] = vgetq_lane_u64(P##12, 1);                                      \
  (S)[0][13] = vgetq_lane_u64(P##13, 0);                                      \
  (S)[1][13] = vgetq_lane_u64(P##13, 1);                                      \
  (S)[0][14] = vgetq_lane_u64(P##14, 0);                                      \
  (S)[1][14] = vgetq_lane_u64(P##14, 1);                                      \
  (S)[0][15] = vgetq_lane_u64(P##15, 0);                                      \
  (S)[1][15] = vgetq_lane_u64(P##15, 1);                                      \
  (S)[0][16] = vgetq_lane_u64(P##16, 0);                                      \
  (S)[1][16] = vgetq_lane_u64(P##16, 1);                                      \
  (S)[0][17] = vgetq_lane_u64(P##17, 0);                                      \
  (S)[1][17] = vgetq_lane_u64(P##17, 1);                                      \
  (S)[0][18] = vgetq_lane_u64(P##18, 0);                                      \
  (S)[1][18] = vgetq_lane_u64(P##18, 1);                                      \
  (S)[0][19] = vgetq_lane_u64(P##19, 0);                                      \
  (S)[1][19] = vgetq_lane_u64(P##19, 1);                                      \
  (S)[0][20] = vgetq_lane_u64(P##20, 0);                                      \
  (S)[1][20] = vgetq_lane_u64(P##20, 1);                                      \
  (S)[0][21] = vgetq_lane_u64(P##21, 0);                                      \
  (S)[1][21] = vgetq_lane_u64(P##21, 1);                                      \
  (S)[0][22] = vgetq_lane_u64(P##22, 0);                                      \
  (S)[1][22] = vgetq_lane_u64(P##22, 1);                                      \
  (S)[0][23] = vgetq_lane_u64(P##23, 0);                                      \
  (S)[1][23] = vgetq_lane_u64(P##23, 1);                                      \
  (S)[0][24] = vgetq_lane_u64(P##24, 0);                                      \
  (S)[1][24] = vgetq_lane_u64(P##24, 1);

/* ROL(t ^ D, ROT) via XAR = ROR(a ^ b, imm); 64 - ROT in [2, 63]. */
#define KFA3_RHOPI(P, DEST, ROT, D)             \
  do {                                          \
    u = P##DEST;                                \
    P##DEST = vxarq_u64(t, (D), 64 - (ROT));    \
    t       = u;                                \
  } while (0);

#define KFA3_CHI(P, Y0, Y1, Y2, Y3, Y4)     \
  do {                                      \
    uint64x2_t r0 = P##Y0, r1 = P##Y1, r2 = P##Y2, r3 = P##Y3, r4 = P##Y4; \
    P##Y0 = vbcaxq_u64(r0, r2, r1);         \
    P##Y1 = vbcaxq_u64(r1, r3, r2);         \
    P##Y2 = vbcaxq_u64(r2, r4, r3);         \
    P##Y3 = vbcaxq_u64(r3, r0, r4);         \
    P##Y4 = vbcaxq_u64(r4, r1, r0);         \
  } while (0);

#define KFA3_ROUND(P, RCIDX)                                                   \
  do {                                                                         \
    uint64x2_t c0, c1, c2, c3, c4, d0, d1, d2, d3, d4, t, u;                   \
    c0 = veor3q_u64(veor3q_u64(P##0, P##5, P##10), P##15, P##20);              \
    c1 = veor3q_u64(veor3q_u64(P##1, P##6, P##11), P##16, P##21);              \
    c2 = veor3q_u64(veor3q_u64(P##2, P##7, P##12), P##17, P##22);              \
    c3 = veor3q_u64(veor3q_u64(P##3, P##8, P##13), P##18, P##23);              \
    c4 = veor3q_u64(veor3q_u64(P##4, P##9, P##14), P##19, P##24);              \
    d0 = vrax1q_u64(c4, c1);                                                   \
    d1 = vrax1q_u64(c0, c2);                                                   \
    d2 = vrax1q_u64(c1, c3);                                                   \
    d3 = vrax1q_u64(c2, c4);                                                   \
    d4 = vrax1q_u64(c3, c0);                                                   \
    t = P##1;                                                                  \
    KFA3_RHOPI(P, 10, 1, d1)                                                   \
    KFA3_RHOPI(P, 7, 3, d0)                                                    \
    KFA3_RHOPI(P, 11, 6, d2)                                                   \
    KFA3_RHOPI(P, 17, 10, d1)                                                  \
    KFA3_RHOPI(P, 18, 15, d2)                                                  \
    KFA3_RHOPI(P, 3, 21, d3)                                                   \
    KFA3_RHOPI(P, 5, 28, d3)                                                   \
    KFA3_RHOPI(P, 16, 36, d0)                                                  \
    KFA3_RHOPI(P, 8, 45, d1)                                                   \
    KFA3_RHOPI(P, 21, 55, d3)                                                  \
    KFA3_RHOPI(P, 24, 2, d1)                                                   \
    KFA3_RHOPI(P, 4, 14, d4)                                                   \
    KFA3_RHOPI(P, 15, 27, d4)                                                  \
    KFA3_RHOPI(P, 23, 41, d0)                                                  \
    KFA3_RHOPI(P, 19, 56, d3)                                                  \
    KFA3_RHOPI(P, 13, 8, d4)                                                   \
    KFA3_RHOPI(P, 12, 25, d3)                                                  \
    KFA3_RHOPI(P, 2, 43, d2)                                                   \
    KFA3_RHOPI(P, 20, 62, d2)                                                  \
    KFA3_RHOPI(P, 14, 18, d0)                                                  \
    KFA3_RHOPI(P, 22, 39, d4)                                                  \
    KFA3_RHOPI(P, 9, 61, d2)                                                   \
    KFA3_RHOPI(P, 6, 20, d4)                                                   \
    KFA3_RHOPI(P, 1, 44, d1)                                                   \
    P##0 = veorq_u64(P##0, d0);                                                \
    KFA3_CHI(P, 0, 1, 2, 3, 4)                                                 \
    KFA3_CHI(P, 5, 6, 7, 8, 9)                                                 \
    KFA3_CHI(P, 10, 11, 12, 13, 14)                                            \
    KFA3_CHI(P, 15, 16, 17, 18, 19)                                            \
    KFA3_CHI(P, 20, 21, 22, 23, 24)                                            \
    P##0 = veorq_u64(P##0, vdupq_n_u64(RC[RCIDX]));                           \
  } while (0);

static inline void keccakf_armsha3(void *state) {
  uint64_t *s = (uint64_t *)state;
  KFA3_DECL(v);
  KFA3_LOAD1(v, s)
  for (int i = 0; i < 24; i++) KFA3_ROUND(v, i);
  KFA3_STORE1(s, v)
}

static inline void keccak12_armsha3(void *state) {
  uint64_t *s = (uint64_t *)state;
  KFA3_DECL(v);
  KFA3_LOAD1(v, s)
  for (int i = 12; i < 24; i++) KFA3_ROUND(v, i);
  KFA3_STORE1(s, v)
}

static inline void keccakf2_armsha3(uint64_t s[2][25]) {
  KFA3_DECL(v);
  KFA3_LOAD2(v, s)
  for (int i = 0; i < 24; i++) KFA3_ROUND(v, i);
  KFA3_STORE2(s, v)
}

static inline void keccak12_2_armsha3(uint64_t s[2][25]) {
  KFA3_DECL(v);
  KFA3_LOAD2(v, s)
  for (int i = 12; i < 24; i++) KFA3_ROUND(v, i);
  KFA3_STORE2(s, v)
}

#endif /* FINWO_ARM_SHA3_PERM_H */
