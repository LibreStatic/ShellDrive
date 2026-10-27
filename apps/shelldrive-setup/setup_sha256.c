/* SHA-256 (FIPS 180-4) for the payload check (04 §6.1). Our own code: the stub cannot link sd_crypto,
   whose CNG-based objects import bcrypt.dll (TM-R33). */
/* Self-contained (windows.h only): tools/sd-payload includes this file too. */
#include <windows.h>

#include <string.h>

void sd_setup_sha256(const void *data, size_t n, unsigned char out[32]);
int sd_setup_sha256_hex(const unsigned char sha[32], char out[65]);

typedef struct sd_sha256_ctx {
  DWORD h[8];
  unsigned char buf[64];
  size_t buflen;
  unsigned long long total;
} sd_sha256_ctx;

static const DWORD k_sha256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sd_sha256_ctx *c, const unsigned char *p)
{
  DWORD w[64];
  DWORD a, b, cc, d, e, f, g, h;
  int i;

  for (i = 0; i < 16; i++) {
    w[i] = ((DWORD)p[4 * i] << 24) | ((DWORD)p[4 * i + 1] << 16) | ((DWORD)p[4 * i + 2] << 8) |
           (DWORD)p[4 * i + 3];
  }
  for (i = 16; i < 64; i++) {
    DWORD s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    DWORD s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
  e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];

  for (i = 0; i < 64; i++) {
    DWORD S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
    DWORD ch = (e & f) ^ (~e & g);
    DWORD t1 = h + S1 + ch + k_sha256[i] + w[i];
    DWORD S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
    DWORD maj = (a & b) ^ (a & cc) ^ (b & cc);
    DWORD t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = cc; cc = b; b = a; a = t1 + t2;
  }

  c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
  c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sd_sha256_ctx *c)
{
  c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85; c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
  c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c; c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
  c->buflen = 0;
  c->total = 0;
}

static void sha256_update(sd_sha256_ctx *c, const unsigned char *p, size_t n)
{
  c->total += n;
  while (n > 0) {
    size_t take = 64 - c->buflen;
    if (take > n)
      take = n;
    memcpy(c->buf + c->buflen, p, take);
    c->buflen += take;
    p += take;
    n -= take;
    if (c->buflen == 64) {
      sha256_block(c, c->buf);
      c->buflen = 0;
    }
  }
}

static void sha256_final(sd_sha256_ctx *c, unsigned char out[32])
{
  unsigned long long bits = c->total * 8;
  unsigned char pad[72];
  size_t padlen = (c->buflen < 56) ? (56 - c->buflen) : (120 - c->buflen);
  int i;

  memset(pad, 0, sizeof(pad));
  pad[0] = 0x80;
  for (i = 0; i < 8; i++)
    pad[padlen + i] = (unsigned char)(bits >> (56 - 8 * i));
  sha256_update(c, pad, padlen + 8);

  for (i = 0; i < 8; i++) {
    out[4 * i] = (unsigned char)(c->h[i] >> 24);
    out[4 * i + 1] = (unsigned char)(c->h[i] >> 16);
    out[4 * i + 2] = (unsigned char)(c->h[i] >> 8);
    out[4 * i + 3] = (unsigned char)c->h[i];
  }
}

void sd_setup_sha256(const void *data, size_t n, unsigned char out[32])
{
  sd_sha256_ctx c;
  sha256_init(&c);
  sha256_update(&c, (const unsigned char *)data, n);
  sha256_final(&c, out);
}

int sd_setup_sha256_hex(const unsigned char sha[32], char out[65])
{
  static const char digits[] = "0123456789abcdef";
  int i;
  for (i = 0; i < 32; i++) {
    out[2 * i] = digits[sha[i] >> 4];
    out[2 * i + 1] = digits[sha[i] & 15];
  }
  out[64] = '\0';
  return 0;
}
