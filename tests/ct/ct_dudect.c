/* sd-ct-dudect: dudect-style timing tests of the constant-time primitives (01 section 2.4 rule 9, 2.7.5; TST-03).
 *
 * Method (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?", DATE 2017; implemented here from the
 * published description): each measurement runs the primitive once on inputs of class 0 ("fixed") or class 1
 * ("random"), chosen at random per measurement, and records the CPU cycle counter around the call. Measurements
 * above the 99.5th percentile are dropped (interrupts, page faults). A Welch t-test over the two classes gives t;
 * |t| above 4.5 is the usual "possible leak" threshold at 10^5..10^6 samples. A run of this harness is evidence
 * for one machine at one sample size, not a proof: hosted runners are noisy (04 section 11.2 ct.yml).
 *
 * Input classes (the test design, not the primitive's API):
 *   X25519          class 0: one fixed scalar          class 1: random scalars
 *   Ed25519 sign    class 0: one fixed seed            class 1: random seeds (public keys prepared outside the timer)
 *   AES-CTR (bitsliced/table-free paths) class 0: fixed key  class 1: random keys
 *   MAC compare     class 0: equal tags                class 1: tags that differ at a random byte
 *   RSA-1024 modexp class 0: all-ones exponent         class 1: random exponents (CRT halves are the same shape)
 *
 * Usage: sd-ct-dudect [samples-per-primitive] [only: x25519|ed25519|aes|mac|rsa]
 * Exit status: 0 when every |t| is at most 10, 1 when a primitive shows |t| above 10 (rerun on quiet hardware
 * before believing it), 2 on usage error. Test-only code; nothing here ships (TST-30). */
#include <intrin.h>   /* __rdtsc, _ReadWriteBarrier: no SSE2 instruction is emitted (x86-ia32 floor) */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_crypto/sd_crypto_pk.h"
#include "sd_crypto/sd_ct.h"

#define DEFAULT_SAMPLES 20000u
#define RSA_SAMPLES_CAP 4000u
#define T_REPORT 10.0
#define T_LEAK 4.5

typedef struct rng { uint64_t s; } rng;

static uint64_t rng_next(rng *r)
{
  r->s ^= r->s >> 12;
  r->s ^= r->s << 25;
  r->s ^= r->s >> 27;
  return r->s * 2685821657736338717ull;
}

static void rng_fill(rng *r, uint8_t *p, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) p[i] = (uint8_t)rng_next(r);
}

/* One primitive: prepare(class) builds the inputs outside the timer, run() is timed. */
typedef struct prim {
  const char *name;
  size_t samples;
  void *(*setup)(void);
  void (*prepare)(void *ctx, int cls, rng *r);
  void (*run)(void *ctx);
  void (*teardown)(void *ctx);
  int (*check)(void *ctx);  /* 1 when the primitive returned the expected result (sanity) */
} prim;

/* ---- X25519 ---- */
typedef struct x25519_ctx { rng r; uint8_t scalar[32], point[32], out[32]; int ok; } x25519_ctx;

static void *x25519_setup(void)
{
  x25519_ctx *c = (x25519_ctx *)calloc(1, sizeof(*c));
  c->r.s = 0x9e3779b97f4a7c15ull;
  memset(c->point, 0, sizeof(c->point));
  c->point[0] = 9;  /* base point */
  return c;
}

static void x25519_prepare(void *vc, int cls, rng *r)
{
  x25519_ctx *c = (x25519_ctx *)vc;
  (void)r;
  if (cls == 0) memset(c->scalar, 0x5a, sizeof(c->scalar));
  else rng_fill(&c->r, c->scalar, sizeof(c->scalar));
}

static void x25519_run(void *vc)
{
  x25519_ctx *c = (x25519_ctx *)vc;
  c->ok = sd_x25519(c->out, c->scalar, c->point) == SD_OK;
}

static int x25519_check(void *vc)
{
  return ((x25519_ctx *)vc)->ok;
}

static void x25519_teardown(void *vc)
{
  free(vc);
}

/* ---- Ed25519 signing ---- */
typedef struct ed_ctx { rng r; uint8_t seed[32], pub[32], sig[64]; uint8_t msg[64]; int ok; } ed_ctx;

static void *ed_setup(void)
{
  ed_ctx *c = (ed_ctx *)calloc(1, sizeof(*c));
  c->r.s = 0x2545f4914f6cdd1dull;
  memset(c->msg, 0x33, sizeof(c->msg));
  return c;
}

static void ed_prepare(void *vc, int cls, rng *r)
{
  ed_ctx *c = (ed_ctx *)vc;
  (void)r;
  if (cls == 0) memset(c->seed, 0xa7, sizeof(c->seed));
  else rng_fill(&c->r, c->seed, sizeof(c->seed));
  (void)sd_ed25519_pub_from_seed(c->pub, c->seed);
}

static void ed_run(void *vc)
{
  ed_ctx *c = (ed_ctx *)vc;
  c->ok = sd_ed25519_sign(c->sig, c->seed, c->pub, c->msg, sizeof(c->msg)) == SD_OK;
}

static int ed_check(void *vc)
{
  return ((ed_ctx *)vc)->ok;
}

static void ed_teardown(void *vc)
{
  free(vc);
}

/* ---- AES-CTR (key-dependent work per block) ---- */
typedef struct aes_ctx { rng r; uint8_t key[32], ctr[16], in[64], out[64]; int ok; } aes_ctx;

static void *aes_setup(void)
{
  aes_ctx *c = (aes_ctx *)calloc(1, sizeof(*c));
  c->r.s = 0x0123456789abcdefull;
  memset(c->in, 0x11, sizeof(c->in));
  memset(c->ctr, 0, sizeof(c->ctr));
  return c;
}

static void aes_prepare(void *vc, int cls, rng *r)
{
  aes_ctx *c = (aes_ctx *)vc;
  (void)r;
  if (cls == 0) memset(c->key, 0x3c, sizeof(c->key));
  else rng_fill(&c->r, c->key, sizeof(c->key));
}

static void aes_run(void *vc)
{
  aes_ctx *c = (aes_ctx *)vc;
  c->ok = sd_aes_ctr(c->key, sizeof(c->key), c->ctr, c->in, sizeof(c->in), c->out) == SD_OK;
}

static int aes_check(void *vc)
{
  return ((aes_ctx *)vc)->ok;
}

static void aes_teardown(void *vc)
{
  free(vc);
}

/* ---- MAC/tag comparison (sd_ct_memeq) ---- */
typedef struct mac_ctx { rng r; uint8_t a[16], b[16]; int res; int want; } mac_ctx;

static void *mac_setup(void)
{
  mac_ctx *c = (mac_ctx *)calloc(1, sizeof(*c));
  c->r.s = 0xdeadbeefcafef00dull;
  return c;
}

static void mac_prepare(void *vc, int cls, rng *r)
{
  mac_ctx *c = (mac_ctx *)vc;
  size_t pos = (size_t)(rng_next(&c->r) % sizeof(c->b));
  rng_fill(r, c->a, sizeof(c->a));
  memcpy(c->b, c->a, sizeof(c->b));
  /* Both classes do the same store (same address, same memory history); only the value differs, so the classes
     differ in data and nothing else. A class-only store made the preparation history differ and skewed the timer. */
  c->b[pos] ^= (uint8_t)(cls == 0 ? 0x00 : 0x01);
  c->want = cls == 0;
}

static void mac_run(void *vc)
{
  mac_ctx *c = (mac_ctx *)vc;
  c->res = sd_ct_memeq(c->a, c->b, sizeof(c->a));
}

static int mac_check(void *vc)
{
  mac_ctx *c = (mac_ctx *)vc;
  return (c->res != 0) == (c->want != 0);
}

static void mac_teardown(void *vc)
{
  free(vc);
}

/* ---- RSA-size modular exponentiation (sd_bn_ct_modexp, the private-key operation's core) ---- */
typedef struct rsa_ctx {
  rng r;
  sd_bn base, exp, mod, out;
  int ok;
} rsa_ctx;

static void *rsa_setup(void)
{
  rsa_ctx *c = (rsa_ctx *)calloc(1, sizeof(*c));
  uint8_t m[128];
  c->r.s = 0x5851f42d4c957f2dull;
  rng_fill(&c->r, m, sizeof(m));
  m[0] |= 0x80;           /* 1024-bit modulus, odd */
  m[sizeof(m) - 1] |= 1;
  (void)sd_bn_from_bytes(&c->mod, m, sizeof(m));
  return c;
}

static void rsa_prepare(void *vc, int cls, rng *r)
{
  rsa_ctx *c = (rsa_ctx *)vc;
  uint8_t b[128], e[128];
  (void)r;
  rng_fill(&c->r, b, sizeof(b));
  b[0] &= 0x7f;           /* base < modulus */
  (void)sd_bn_from_bytes(&c->base, b, sizeof(b));
  if (cls == 0) {
    memset(e, 0xff, sizeof(e));
  } else {
    rng_fill(&c->r, e, sizeof(e));
  }
  e[0] |= 0x80;           /* the exponent has its full length: 1024 bits */
  (void)sd_bn_from_bytes(&c->exp, e, sizeof(e));
}

static void rsa_run(void *vc)
{
  rsa_ctx *c = (rsa_ctx *)vc;
  c->ok = sd_bn_ct_modexp(&c->out, &c->base, &c->exp, 1024, &c->mod) == SD_OK;
}

static int rsa_check(void *vc)
{
  return ((rsa_ctx *)vc)->ok;
}

static void rsa_teardown(void *vc)
{
  free(vc);
}

static const prim k_prims[] = {
  { "X25519 scalar multiplication", DEFAULT_SAMPLES, x25519_setup, x25519_prepare, x25519_run, x25519_teardown, x25519_check },
  { "Ed25519 signing", DEFAULT_SAMPLES, ed_setup, ed_prepare, ed_run, ed_teardown, ed_check },
  { "AES-CTR (table-free)", DEFAULT_SAMPLES, aes_setup, aes_prepare, aes_run, aes_teardown, aes_check },
  { "MAC tag compare (sd_ct_memeq)", DEFAULT_SAMPLES, mac_setup, mac_prepare, mac_run, mac_teardown, mac_check },
  { "RSA-1024 modexp (sd_bn_ct_modexp)", RSA_SAMPLES_CAP, rsa_setup, rsa_prepare, rsa_run, rsa_teardown, rsa_check }
};

/* Welch t over the two classes after cropping at the 99.5th percentile (dudect's post-processing). */
typedef struct welch { double mean[2], var[2]; size_t n[2]; } welch;

static int cmp_u64(const void *a, const void *b)
{
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}

static double welch_t(const uint64_t *t, const uint8_t *cls, size_t n, size_t *used)
{
  uint64_t *sorted = (uint64_t *)malloc(n * sizeof(uint64_t));
  double cut, sum[2] = { 0, 0 }, sq[2] = { 0, 0 }, mean[2], var[2], tt;
  size_t i, cnt[2] = { 0, 0 };
  if (!sorted) return 0.0;
  memcpy(sorted, t, n * sizeof(uint64_t));
  qsort(sorted, n, sizeof(uint64_t), cmp_u64);
  cut = (double)sorted[(n * 995) / 1000];
  free(sorted);
  for (i = 0; i < n; i++) {
    double v = (double)t[i];
    int c;
    if (v > cut) continue;
    c = cls[i];
    sum[c] += v;
    sq[c] += v * v;
    cnt[c]++;
  }
  if (cnt[0] < 2 || cnt[1] < 2) return 0.0;
  for (i = 0; i < 2; i++) {
    mean[i] = sum[i] / (double)cnt[i];
    var[i] = (sq[i] / (double)cnt[i] - mean[i] * mean[i]) * (double)cnt[i] / (double)(cnt[i] - 1);
  }
  tt = (mean[0] - mean[1]) / sqrt(var[0] / (double)cnt[0] + var[1] / (double)cnt[1]);
  if (used) *used = cnt[0] + cnt[1];
  return tt;
}

static int run_prim(const prim *p, size_t samples)
{
  uint64_t *t = (uint64_t *)malloc(samples * sizeof(uint64_t));
  uint8_t *cls = (uint8_t *)malloc(samples);
  void *ctx = p->setup();
  rng sched = { 0x1d2c3b4a5f6e7d8cull };
  size_t i, bad = 0, used = 0;
  double tt;
  if (!t || !cls || !ctx) {
    fprintf(stderr, "sd-ct-dudect: out of memory\n");
    free(t);
    free(cls);
    return 2;
  }
  for (i = 0; i < samples; i++) {
    int c = (int)(rng_next(&sched) & 1u);
    unsigned __int64 t0, t1;
    cls[i] = (uint8_t)c;
    p->prepare(ctx, c, &sched);
    _ReadWriteBarrier();
    t0 = __rdtsc();
    _ReadWriteBarrier();
    p->run(ctx);
    _ReadWriteBarrier();
    t1 = __rdtsc();
    _ReadWriteBarrier();
    t[i] = (uint64_t)(t1 - t0);
    if (!p->check(ctx)) bad++;
  }
  tt = welch_t(t, cls, samples, &used);
  printf("%-36s samples %8zu  used %8zu  max|t| %7.2f  %s", p->name, samples, used, fabs(tt),
         fabs(tt) > T_REPORT ? "LEAK SUSPECTED (rerun on quiet hardware)"
                             : (fabs(tt) > T_LEAK ? "above 4.5: rerun with more samples" : "no leak at this sample size"));
  if (bad) printf("  [%zu calls returned an error: the inputs are wrong]", bad);
  printf("\n");
  p->teardown(ctx);
  free(t);
  free(cls);
  return fabs(tt) > T_REPORT ? 1 : (bad ? 2 : 0);
}

int main(int argc, char **argv)
{
  size_t i, scale = 0;
  const char *only = NULL;
  int rc = 0;
  if (argc > 1) scale = (size_t)strtoul(argv[1], NULL, 10);
  if (argc > 2) only = argv[2];
  printf("sd-ct-dudect: dudect-style Welch t-test, two input classes per primitive (cycle counter)\n");
  for (i = 0; i < sizeof(k_prims) / sizeof(k_prims[0]); i++) {
    prim p = k_prims[i];
    int r;
    if (only && !strstr(p.name, only)) continue;
    if (scale) p.samples = scale;
    r = run_prim(&p, p.samples);
    if (r > rc) rc = r;
  }
  return rc;
}
