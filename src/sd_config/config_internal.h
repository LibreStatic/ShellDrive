/* sd_config internals shared by profile.c, profile_m2.c and import.c. */
#ifndef SD_CONFIG_INTERNAL_H
#define SD_CONFIG_INTERNAL_H

#include "sd_config/sd_config.h"

void        sd_profile_m2_defaults(sd_profile *p);
void        sd_profile_m3_defaults(sd_profile *p);
const char *sd_profile_m3_from_ini(const sd_ini *ini, sd_profile *p);    /* bad key or NULL */
const char *sd_profile_m3_validate(const sd_profile *p);                 /* bad key or NULL */
sd_err      sd_profile_m3_to_ini(const sd_profile *p, sd_ini *d);
const char *sd_profile_m2_validate(const sd_profile *p);                 /* bad key or NULL */
const char *sd_profile_m2_from_ini(const sd_ini *ini, sd_profile *p);    /* bad key or NULL */
sd_err      sd_profile_m2_to_ini(const sd_profile *p, sd_ini *d);

/* Per-user state folder (%LOCALAPPDATA%\LibreStatic\ShellDrive\state, or <root>\state under the test override),
   created with the protected DACL. */
sd_err      sd_config_state_dir(wchar_t *out, size_t cch);
/* menu.cache path (03 §8.2.2) and its rewrite from the profile store (menucache.c). The rewrite does not take
   config.lock: the caller holds it (sd_profile_save_ex, sd_profile_delete). */
sd_err      sd_menucache_path(wchar_t *out, size_t cch);
sd_err      sd_menucache_rewrite(void);

int  sd_cfg_has_ctl(const char *s);
int  sd_cfg_scpy(char *dst, size_t cap, const char *src);
int  sd_cfg_valid_host(const char *h);
void sd_cfg_u32_dec(char out[16], uint32_t v);
/* "[user@]host[:port]" in UTF-8 (IPv6 as [::1]:22); port 0 when absent. */
int  sd_cfg_parse_host_spec_utf8(const char *spec, char *user, size_t ucap, char *host, size_t hcap, uint16_t *port);

#endif /* SD_CONFIG_INTERNAL_H */
