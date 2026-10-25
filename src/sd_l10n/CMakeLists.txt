# sd_l10n runtime (03 §9). Owned by the apps/IPC agent. Catalog tables are generated per binary by
# sd_add_l10n_catalog() (cmake/SdL10n.cmake) from l10n/<domain>/<lang>.po.

sd_add_module(sd_l10n
  DEPS
    sd_base
    sd_platform
  HEADERS
    include/sd_l10n/sd_l10n.h
    include/sd_l10n/sd_l10n_catalog.h)
