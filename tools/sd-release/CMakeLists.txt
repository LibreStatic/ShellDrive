# sd-release: release signing tool (docs/design/04 §9.2, §9.3, §12.3). Build-time tool, never shipped. It links the
# verifier and signer of sd_crypto, the manifest parser of sd_update and the payload table signature of the setup
# engine (sd_payload_sig). No network code.
add_executable(sd-release sd-release.c)
target_link_libraries(sd-release PRIVATE sd_update sd_payload_sig sd_crypto sd_platform sd_base)
set_target_properties(sd-release PROPERTIES FOLDER "tools")
