/* Layout of the message tables that tools/sdl10n generates from l10n/<domain>/<lang>.po (03 §9).
 * Shared contract between the generator and the sd_l10n runtime; change both together and bump
 * SD_L10N_CATALOG_ABI.
 *
 * Each catalog is a const object in read-only data: no initialization, safe from any thread. */
#ifndef SD_L10N_CATALOG_H
#define SD_L10N_CATALOG_H

#include "sd/base.h"

#define SD_L10N_CATALOG_ABI 1

/* Canonical languages (03 §9.1); order is part of the ABI. */
typedef enum sd_lang { SD_LANG_EN, SD_LANG_ES, SD_LANG_FR, SD_LANG_PT_BR, SD_LANG_IT, SD_LANG_DE, SD_LANG_COUNT } sd_lang;

/* CLDR plural categories (D26). Tables are indexed by category, not by PO msgstr index. */
typedef enum sd_plural_cat {
  SD_PLURAL_ZERO, SD_PLURAL_ONE, SD_PLURAL_TWO, SD_PLURAL_FEW, SD_PLURAL_MANY, SD_PLURAL_OTHER,
  SD_PLURAL_CAT_COUNT
} sd_plural_cat;

typedef uint32_t sd_msg_id;   /* SD_MSG_* constants from the generated <sd_l10n_<name>_ids.h> */

typedef struct sd_l10n_catalog {
  uint32_t abi;                          /* SD_L10N_CATALOG_ABI */
  uint32_t count;                        /* number of messages */
  const char *name;                      /* catalog name, e.g. "cli" */
  const char *const *keys;               /* [count] msgctxt (stable symbolic id), for diagnostics */
  const char *const *plural_arg;         /* [count] placeholder that selects the form; NULL = not plural */
  /* strings[lang][id * SD_PLURAL_CAT_COUNT + cat]: UTF-8. Non-plural messages use SD_PLURAL_OTHER.
     NULL = missing (only possible in a build with SD_L10N_ALLOW_INCOMPLETE; falls back to en). */
  const char *const *strings[SD_LANG_COUNT];
  uint32_t complete_mask;                /* bit (1u << lang) set when that language is complete */
} sd_l10n_catalog;

#endif /* SD_L10N_CATALOG_H */
