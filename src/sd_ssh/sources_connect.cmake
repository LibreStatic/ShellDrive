# sd_ssh sources of the `connect` area (M2): ProxyJump chains (01 §5.1), HTTP CONNECT / SOCKS5 proxies,
# SSPI proxy authentication and the system proxy source (01 §5.2, D20). conn.c and channel.c stay in
# the main list. secur32.dll and winhttp.dll are resolved at run time (no static import, XP floor).
list(APPEND SD_SSH_SOURCES
    jump_chain.c
    proxy_conn.c
    proxy_http.c
    proxy_socks5.c
    proxy_sspi.c
    proxy_system.c)
