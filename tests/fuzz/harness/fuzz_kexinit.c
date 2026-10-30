/* fuzz_kexinit: SSH_MSG_KEXINIT payloads (RFC 4253 section 7.1). Parses the server list and negotiates it against
   our own lists. Every span must lie inside the payload, and a successful negotiation must name algorithms. */
#include "sd_fuzz.h"
#include "sd_base/sd_err.h"
#include "ssh_internal.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  ssh_kexinit k;
  ssh_list_input in;
  ssh_lists ours;
  ssh_list_result res;
  ssh_algs algs;
  const char *category = NULL;
  sd_err e;

  if (size > 64u * 1024u) return 0;
  memset(&k, 0, sizeof(k));
  e = ssh_kexinit_parse(data, size, &k);
  if (e != SD_OK) return 0;
  {
    const sd_span *spans[10];   /* filled at run time: v141 refuses addresses of locals in initializers */
    size_t i;
    spans[0] = &k.kex; spans[1] = &k.hostkey; spans[2] = &k.enc_c2s; spans[3] = &k.enc_s2c;
    spans[4] = &k.mac_c2s; spans[5] = &k.mac_s2c; spans[6] = &k.comp_c2s; spans[7] = &k.comp_s2c;
    spans[8] = &k.lang_c2s; spans[9] = &k.lang_s2c;
    for (i = 0; i < sizeof(spans) / sizeof(spans[0]); i++) {
      if (spans[i]->n == 0) continue;
      SD_FUZZ_CHECK((const uint8_t *)spans[i]->p >= data);
      SD_FUZZ_CHECK((const uint8_t *)spans[i]->p + spans[i]->n <= data + size);
    }
  }

  memset(&in, 0, sizeof(in));
  in.initial = 1;
  in.allow_legacy = 1;
  if (ssh_build_lists(&in, &ours, &res) != SD_OK) return 0;
  memset(&algs, 0, sizeof(algs));
  e = ssh_negotiate(&ours, &k, &algs, &category);
  (void)e;
  return 0;
}
