/* Minimal 32-bit x86 instruction length decoder and ISA-extension classifier for sd-isacheck.
 *
 * It decodes the legacy prefixes, the one-byte, 0F, 0F 38 and 0F 3A opcode maps, ModRM/SIB/displacement
 * and immediates, and the VEX (C4/C5) and EVEX (62) forms that 32-bit mode distinguishes from LES/LDS/
 * BOUND by ModRM.mod == 11. It does not produce mnemonics: it only needs to stay in sync with a linear
 * sweep and to say which instruction-set extension an instruction needs. Build-time tool, never shipped. */
#ifndef SD_X86_DECODE_H
#define SD_X86_DECODE_H

#include <stddef.h>

typedef enum x86_isa {
  X86_ISA_BASE = 0,    /* i686 (P6) integer and x87, incl. CMOV, CMPXCHG8B, RDTSC, CPUID */
  X86_ISA_MMX,
  X86_ISA_SSE,         /* SSE and the MMX extensions that came with it (PSHUFW, PREFETCHh, SFENCE) */
  X86_ISA_SSE2,
  X86_ISA_SSE3PLUS,    /* SSE3, SSSE3, SSE4.x, SSE4a, POPCNT/LZCNT/TZCNT, RDRAND/RDSEED, MOVBE, CRC32 */
  X86_ISA_AVX,         /* any VEX-encoded instruction */
  X86_ISA_AVX512,      /* any EVEX-encoded instruction */
  X86_ISA_3DNOW,       /* 3DNow! and PREFETCH/PREFETCHW (0F 0D), FEMMS */
  X86_ISA_SYSEXT,      /* FXSAVE/FXRSTOR, XSAVE family, XGETBV/XSETBV, CLFLUSH: not P6 baseline */
  X86_ISA_COUNT
} x86_isa;

typedef struct x86_insn {
  unsigned len;        /* 0 = could not decode (invalid or truncated) */
  x86_isa isa;
  unsigned char opcode_map;   /* 0 = one-byte, 1 = 0F, 2 = 0F38, 3 = 0F3A, 0x10 + map = VEX, 0x20 + map = EVEX */
  unsigned char opcode;
  int is_call_rel32;   /* E8 rel32: target = address + len + rel */
  int is_jmp_rel32;    /* E9 rel32 */
  int rel32;
  int is_jcc;          /* conditional branch: 70-7F, E0-E3 (LOOP*, JECXZ), 0F 80-8F (rel8 or rel32) */
  int is_div;          /* DIV or IDIV (F6/F7 with ModRM.reg 6 or 7), any operand size */
  int is_branch_rel;   /* a relative branch: rel8 (EB, 70-7F, E0-E3) or rel32 (E9, 0F 80-8F); rel is in rel32 */
} x86_insn;

const char *x86_isa_name(x86_isa isa);
/* Decodes one instruction at p (n bytes available). */
void x86_decode(const unsigned char *p, size_t n, x86_insn *out);

#endif /* SD_X86_DECODE_H */
