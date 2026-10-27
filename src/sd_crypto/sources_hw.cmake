# x86/x64 hardware fast paths (M6, 01 §2.3): SHA-NI (sha256_ni.c) and AES-NI (aes_ni.c). Both are SIMD translation
# units and never reach the x86-ia32 flavour, whose floor has no SIMD code at all, nor the ARM flavours. The C side
# guards the same set with SD_CRYPTO_X86_HW (crypto_internal.h); the two must agree.
if(NOT SD_X86_IA32 AND NOT SD_ARM64 AND NOT SD_ARM32)
  list(APPEND SD_CRYPTO_SOURCES
      aes_ni.c
      sha256_ni.c)
endif()
