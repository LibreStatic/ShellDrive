# sd-release: release signing tool (docs/design/04 §9.2, §9.3, §12.3). Build-time tool, never shipped. It links the
# verifier and signer of sd_crypto, the manifest parser of sd_update and the pure payload table signature verifier
# (sd_payload_sig_text; the keyring library of the stub depends on this very tool, so it must not link it back).
# No network code.
add_executable(sd-release sd-release.c)
target_link_libraries(sd-release PRIVATE sd_update sd_payload_sig_text sd_crypto sd_platform sd_base)
set_target_properties(sd-release PROPERTIES FOLDER "tools")
