# sd-updsign: offline signing tool of the release pipeline (04 §9.3, §12.3). Build-time tool; never shipped.
add_executable(sd-updsign sd-updsign.c)
target_link_libraries(sd-updsign PRIVATE sd_update sd_crypto sd_platform sd_base)
set_target_properties(sd-updsign PROPERTIES FOLDER "tools")
