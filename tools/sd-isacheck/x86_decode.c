/* See x86_decode.h. Opcode properties follow the Intel SDM Vol. 2 opcode maps (Appendix A) for
   32-bit protected mode with a 32-bit default operand and address size. */
#include "x86_decode.h"

#include <string.h>

enum {
  F_M = 1,      /* ModRM follows */
  F_I8 = 2,     /* imm8 */
  F_IZ = 4,     /* imm16/imm32 by operand size */
  F_IW = 8,     /* imm16 */
  F_MO = 16,    /* moffs16/32 by address size */
  F_FAR = 32,   /* ptr16:16/ptr16:32 */
  F_BAD = 64    /* undefined in 32-bit mode for our purposes */
};

static unsigned char g_one[256], g_two[256];
static int g_ready;

static void set_range(unsigned char *t, int from, int to, unsigned char f)
{
  int i;
  for (i = from; i <= to; i++) t[i] = f;
}

static void init_tables(void)
{
  int i;
  /* One-byte map. ALU blocks 00-3F: op r/m,r (4 x ModRM), AL,imm8, eAX,immz, then misc. */
  for (i = 0; i < 0x40; i += 8) {
    set_range(g_one, i, i + 3, F_M);
    g_one[i + 4] = F_I8;
    g_one[i + 5] = F_IZ;
    g_one[i + 6] = 0;
    g_one[i + 7] = 0;
  }
  set_range(g_one, 0x40, 0x61, 0);
  g_one[0x62] = F_M;            /* BOUND (EVEX handled separately) */
  g_one[0x63] = F_M;            /* ARPL */
  g_one[0x68] = F_IZ;
  g_one[0x69] = F_M | F_IZ;
  g_one[0x6A] = F_I8;
  g_one[0x6B] = F_M | F_I8;
  set_range(g_one, 0x6C, 0x6F, 0);
  set_range(g_one, 0x70, 0x7F, F_I8);
  g_one[0x80] = F_M | F_I8;
  g_one[0x81] = F_M | F_IZ;
  g_one[0x82] = F_M | F_I8;
  g_one[0x83] = F_M | F_I8;
  set_range(g_one, 0x84, 0x8F, F_M);
  set_range(g_one, 0x90, 0x99, 0);
  g_one[0x9A] = F_FAR;
  set_range(g_one, 0x9B, 0x9F, 0);
  set_range(g_one, 0xA0, 0xA3, F_MO);
  set_range(g_one, 0xA4, 0xA7, 0);
  g_one[0xA8] = F_I8;
  g_one[0xA9] = F_IZ;
  set_range(g_one, 0xAA, 0xAF, 0);
  set_range(g_one, 0xB0, 0xB7, F_I8);
  set_range(g_one, 0xB8, 0xBF, F_IZ);
  g_one[0xC0] = F_M | F_I8;
  g_one[0xC1] = F_M | F_I8;
  g_one[0xC2] = F_IW;
  g_one[0xC3] = 0;
  g_one[0xC4] = F_M;            /* LES (VEX3 handled separately) */
  g_one[0xC5] = F_M;            /* LDS (VEX2 handled separately) */
  g_one[0xC6] = F_M | F_I8;
  g_one[0xC7] = F_M | F_IZ;
  g_one[0xC8] = F_IW | F_I8;    /* ENTER */
  g_one[0xC9] = 0;
  g_one[0xCA] = F_IW;
  set_range(g_one, 0xCB, 0xCC, 0);
  g_one[0xCD] = F_I8;
  set_range(g_one, 0xCE, 0xCF, 0);
  set_range(g_one, 0xD0, 0xD3, F_M);
  g_one[0xD4] = F_I8;
  g_one[0xD5] = F_I8;
  set_range(g_one, 0xD6, 0xD7, 0);
  set_range(g_one, 0xD8, 0xDF, F_M);   /* x87 */
  set_range(g_one, 0xE0, 0xE7, F_I8);
  g_one[0xE8] = F_IZ;
  g_one[0xE9] = F_IZ;
  g_one[0xEA] = F_FAR;
  g_one[0xEB] = F_I8;
  set_range(g_one, 0xEC, 0xEF, 0);
  set_range(g_one, 0xF1, 0xF1, 0);
  set_range(g_one, 0xF4, 0xF5, 0);
  g_one[0xF6] = F_M;            /* TEST imm8 for /0 /1, see decode */
  g_one[0xF7] = F_M;            /* TEST immz for /0 /1 */
  set_range(g_one, 0xF8, 0xFD, 0);
  g_one[0xFE] = F_M;
  g_one[0xFF] = F_M;

  /* Two-byte map 0F xx. Default: ModRM, then the exceptions. */
  set_range(g_two, 0x00, 0xFF, F_M);
  set_range(g_two, 0x04, 0x0C, 0);     /* SYSCALL, CLTS, SYSRET, INVD, WBINVD, UD2 ... */
  g_two[0x04] = F_BAD;
  g_two[0x0A] = F_BAD;
  g_two[0x0C] = F_BAD;
  g_two[0x0D] = F_M;                   /* PREFETCH (3DNow!) */
  g_two[0x0E] = 0;                     /* FEMMS */
  g_two[0x0F] = F_M | F_I8;            /* 3DNow!: ModRM + opcode suffix byte */
  set_range(g_two, 0x24, 0x27, F_BAD);
  set_range(g_two, 0x30, 0x37, 0);     /* WRMSR RDTSC RDMSR RDPMC SYSENTER SYSEXIT - GETSEC */
  set_range(g_two, 0x39, 0x39, F_BAD);
  set_range(g_two, 0x3B, 0x3F, F_BAD);
  g_two[0x70] = F_M | F_I8;
  set_range(g_two, 0x71, 0x73, F_M | F_I8);
  g_two[0x77] = 0;                     /* EMMS */
  set_range(g_two, 0x7A, 0x7B, F_BAD);
  set_range(g_two, 0x80, 0x8F, F_IZ);  /* Jcc rel16/32 */
  set_range(g_two, 0xA0, 0xA2, 0);     /* PUSH FS, POP FS, CPUID */
  g_two[0xA4] = F_M | F_I8;
  set_range(g_two, 0xA6, 0xA7, F_BAD);
  set_range(g_two, 0xA8, 0xAA, 0);     /* PUSH GS, POP GS, RSM */
  g_two[0xAC] = F_M | F_I8;
  g_two[0xBA] = F_M | F_I8;
  g_two[0xC2] = F_M | F_I8;
  set_range(g_two, 0xC4, 0xC6, F_M | F_I8);
  set_range(g_two, 0xC8, 0xCF, 0);     /* BSWAP */
  g_ready = 1;
}

const char *x86_isa_name(x86_isa isa)
{
  static const char *const k[X86_ISA_COUNT] = {
    "base", "MMX", "SSE", "SSE2", "SSE3+", "AVX (VEX)", "AVX-512 (EVEX)", "3DNow!", "FXSR/XSAVE/CLFLUSH"
  };
  return (unsigned)isa < X86_ISA_COUNT ? k[isa] : "?";
}

/* ModRM + SIB + displacement length (bytes after the opcode), or -1 if truncated. */
static int modrm_len(const unsigned char *p, size_t n, int addr16)
{
  unsigned mod, rm;
  int len = 1;
  if (n < 1) return -1;
  mod = p[0] >> 6;
  rm = p[0] & 7;
  if (mod == 3) return 1;
  if (addr16) {
    if (mod == 0 && rm == 6) len += 2;
    else if (mod == 1) len += 1;
    else if (mod == 2) len += 2;
  } else {
    if (rm == 4) {
      if (n < 2) return -1;
      len += 1;
      if (mod == 0 && (p[1] & 7) == 5) len += 4;
    } else if (mod == 0 && rm == 5) {
      len += 4;
    }
    if (mod == 1) len += 1;
    else if (mod == 2) len += 4;
  }
  return (size_t)len <= n ? len : -1;
}

static x86_isa classify_0f(unsigned op, int p66, int pf2, int pf3, unsigned char modrm)
{
  unsigned mod = modrm >> 6, reg = (modrm >> 3) & 7;
  int any = p66 || pf2 || pf3;
  switch (op) {
  case 0x0D: case 0x0E: case 0x0F:
    return X86_ISA_3DNOW;
  case 0x01:
    if (modrm == 0xC8 || modrm == 0xC9) return X86_ISA_SSE3PLUS;   /* MONITOR/MWAIT */
    if (modrm == 0xD0 || modrm == 0xD1) return X86_ISA_SYSEXT;     /* XGETBV/XSETBV */
    return X86_ISA_BASE;
  case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
    if (pf3 && (op == 0x12 || op == 0x16)) return X86_ISA_SSE3PLUS;   /* MOVSLDUP/MOVSHDUP */
    if (pf2 && op == 0x12) return X86_ISA_SSE3PLUS;                   /* MOVDDUP */
    if (pf2 || p66) return X86_ISA_SSE2;
    return X86_ISA_SSE;
  case 0x18:
    return reg <= 3 ? X86_ISA_SSE : X86_ISA_BASE;                     /* PREFETCHh vs hint NOP */
  case 0x28: case 0x29: case 0x2A: case 0x2B: case 0x2C: case 0x2D: case 0x2E: case 0x2F:
    return (pf2 || p66) ? X86_ISA_SSE2 : X86_ISA_SSE;
  case 0x38: case 0x3A:
    return X86_ISA_SSE3PLUS;
  case 0x78: case 0x79:
    return (p66 || pf2) ? X86_ISA_SSE3PLUS : X86_ISA_BASE;            /* SSE4a vs VMREAD/VMWRITE */
  case 0x7C: case 0x7D: case 0xD0:
    return any ? X86_ISA_SSE3PLUS : X86_ISA_BASE;
  case 0xAE:
    if (mod == 3) {
      if (pf3) return X86_ISA_SYSEXT;                                  /* RD/WRFSBASE ... */
      if (reg == 5 || reg == 6) return X86_ISA_SSE2;                   /* LFENCE, MFENCE */
      if (reg == 7) return X86_ISA_SSE;                                /* SFENCE */
      return X86_ISA_BASE;
    }
    if (reg == 2 || reg == 3) return X86_ISA_SSE;                      /* LDMXCSR/STMXCSR */
    return X86_ISA_SYSEXT;                                             /* FXSAVE FXRSTOR XSAVE* CLFLUSH */
  case 0xB8: case 0xBC: case 0xBD:
    return pf3 ? X86_ISA_SSE3PLUS : X86_ISA_BASE;                      /* POPCNT/TZCNT/LZCNT */
  case 0xC2: case 0xC6:
    return (pf2 || p66) ? X86_ISA_SSE2 : X86_ISA_SSE;
  case 0xC3:
    return X86_ISA_SSE2;                                               /* MOVNTI */
  case 0xC4: case 0xC5:
    return p66 ? X86_ISA_SSE2 : X86_ISA_SSE;                           /* PINSRW/PEXTRW */
  case 0xC7:
    return (mod == 3 && reg >= 6) ? X86_ISA_SSE3PLUS : X86_ISA_BASE;   /* RDRAND/RDSEED vs CMPXCHG8B */
  case 0xFF:
    return X86_ISA_BASE;                                               /* UD0 */
  default:
    break;
  }
  if (op >= 0x50 && op <= 0x5F) {
    if (p66 || pf2) return X86_ISA_SSE2;
    if (op == 0x5A || op == 0x5B) return X86_ISA_SSE2;                 /* CVTPS2PD, CVTDQ2PS, CVTSS2SD ... */
    return X86_ISA_SSE;
  }
  if (op >= 0x60 && op <= 0x7F) {
    if (any) return X86_ISA_SSE2;
    if (op == 0x70) return X86_ISA_SSE;                                /* PSHUFW */
    return X86_ISA_MMX;
  }
  if (op >= 0xD1 && op <= 0xFE) {
    if (any) {
      if (pf2 && op == 0xF0) return X86_ISA_SSE3PLUS;                  /* LDDQU */
      return X86_ISA_SSE2;
    }
    switch (op) {
    case 0xD4: case 0xF4: case 0xFB:
      return X86_ISA_SSE2;                                             /* PADDQ/PMULUDQ/PSUBQ on MMX */
    case 0xD7: case 0xDA: case 0xDE: case 0xE0: case 0xE3: case 0xE4: case 0xE7: case 0xEA: case 0xEE:
    case 0xF6: case 0xF7:
      return X86_ISA_SSE;                                              /* integer SSE (MMX extensions) */
    case 0xD6: case 0xE6:
      return X86_ISA_BASE;                                             /* undefined without a prefix */
    default:
      return X86_ISA_MMX;
    }
  }
  return X86_ISA_BASE;
}

/* VEX/EVEX: length only needs to be right enough to keep the sweep in sync. */
static void decode_vex(const unsigned char *p, size_t n, size_t pos, int addr16, x86_insn *out, int evex)
{
  unsigned map, op;
  size_t i = pos;
  int m;
  if (evex) {
    if (n < i + 5) return;
    map = p[i + 1] & 3;
    i += 4;
  } else if (p[i] == 0xC5) {
    if (n < i + 3) return;
    map = 1;
    i += 2;
  } else {
    if (n < i + 4) return;
    map = p[i + 1] & 0x1F;
    i += 3;
  }
  op = p[i++];
  out->opcode_map = (unsigned char)((evex ? 0x20 : 0x10) + map);
  out->opcode = (unsigned char)op;
  out->isa = evex ? X86_ISA_AVX512 : X86_ISA_AVX;
  if (map == 1 && op == 0x77) { out->len = (unsigned)i; return; }   /* VZEROUPPER/VZEROALL */
  m = modrm_len(p + i, n - i, addr16);
  if (m < 0) return;
  i += (size_t)m;
  if (map == 3 || (map == 1 && ((op >= 0x70 && op <= 0x73) || op == 0xC2 || (op >= 0xC4 && op <= 0xC6)))) i += 1;
  if (i <= n) out->len = (unsigned)i;
}

void x86_decode(const unsigned char *p, size_t n, x86_insn *out)
{
  size_t i = 0;
  int p66 = 0, p67 = 0, pf2 = 0, pf3 = 0, m;
  unsigned op, f;
  memset(out, 0, sizeof(*out));
  if (!g_ready) init_tables();
  for (; i < n && i < 14; i++) {
    unsigned b = p[i];
    if (b == 0x66) p66 = 1;
    else if (b == 0x67) p67 = 1;
    else if (b == 0xF2) { pf2 = 1; pf3 = 0; }
    else if (b == 0xF3) { pf3 = 1; pf2 = 0; }
    else if (b == 0xF0 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) continue;
    else break;
  }
  if (i >= n) return;
  op = p[i];
  /* VEX/EVEX: in 32-bit mode C4/C5/62 are LES/LDS/BOUND unless the next byte has mod == 11. */
  if ((op == 0xC4 || op == 0xC5 || op == 0x62) && i + 1 < n && (p[i + 1] & 0xC0) == 0xC0) {
    decode_vex(p, n, i, p67, out, op == 0x62);
    return;
  }
  if (op != 0x0F) {
    f = g_one[op];
    out->opcode = (unsigned char)op;
    i++;
    if (f & F_BAD) return;
    if (f & F_M) {
      unsigned reg;
      if (i >= n) return;
      reg = (p[i] >> 3) & 7;
      m = modrm_len(p + i, n - i, p67);
      if (m < 0) return;
      i += (size_t)m;
      if (op == 0xF6 && reg <= 1) i += 1;
      if (op == 0xF7 && reg <= 1) i += p66 ? 2 : 4;
    }
    if (f & F_I8) i += 1;
    if (f & F_IZ) i += p66 ? 2 : 4;
    if (f & F_IW) i += 2;
    if (f & F_MO) i += p67 ? 2 : 4;
    if (f & F_FAR) i += p66 ? 4 : 6;
    if (i > n) return;
    if (op == 0xE8 && !p66) { out->is_call_rel32 = 1; memcpy(&out->rel32, p + i - 4, 4); }
    if (op == 0xE9 && !p66) { out->is_jmp_rel32 = 1; memcpy(&out->rel32, p + i - 4, 4); }
    out->len = (unsigned)i;
    out->isa = X86_ISA_BASE;
    return;
  }
  /* 0F escape. */
  i++;
  if (i >= n) return;
  op = p[i++];
  out->opcode = (unsigned char)op;
  out->opcode_map = 1;
  if (op == 0x38 || op == 0x3A) {
    if (i >= n) return;
    out->opcode_map = op == 0x38 ? 2 : 3;
    out->opcode = p[i++];
    m = modrm_len(p + i, n - i, p67);
    if (m < 0) return;
    i += (size_t)m + (op == 0x3A ? 1 : 0);
    if (i > n) return;
    out->len = (unsigned)i;
    out->isa = X86_ISA_SSE3PLUS;
    return;
  }
  f = g_two[op];
  if (f & F_BAD) return;
  {
    unsigned char modrm = 0;
    if (f & F_M) {
      if (i >= n) return;
      modrm = p[i];
      m = modrm_len(p + i, n - i, p67);
      if (m < 0) return;
      i += (size_t)m;
    }
    if (f & F_I8) i += 1;
    if (f & F_IZ) i += p66 ? 2 : 4;
    if (i > n) return;
    out->len = (unsigned)i;
    out->isa = classify_0f(op, p66, pf2, pf3, modrm);
  }
}
