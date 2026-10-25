# sd_ssh sources of the M2 `transport` area (01 §4, §7): KEX methods, host key signatures and
# certificates, known_hosts live sources (OpenSSH file, PuTTY registry), UpdateHostKeys. kex.c,
# negotiate.c, packet.c and known_hosts.c stay in the main list. hostkey_verify.c and
# known_hosts_live.c have no transport dependency (linked with known_hosts.c by the CLI/UI, 00 §5).
list(APPEND SD_SSH_SOURCES
    hostkey_update.c
    hostkey_verify.c
    kex_methods.c
    known_hosts_live.c)
