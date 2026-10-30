# Message catalogs compiled per binary (03 §9.1). Domains: l10n/<domain>/<lang>.po.
# The cli catalog is linked by apps/shelldrive; add more catalogs/domains here as binaries need them.

sd_add_l10n_catalog(cli DOMAINS cli)

# Empty catalogs for the GUI work (header-only PO files until the strings arrive).
sd_add_l10n_catalog(common DOMAINS common)
sd_add_l10n_catalog(ui DOMAINS ui)
sd_add_l10n_catalog(shell DOMAINS shell)

# Service strings of shelldrive-host.exe (service-debug and the SCM messages; 03 §1.3, §9.1).
sd_add_l10n_catalog(svc DOMAINS svc)
