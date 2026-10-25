# sd-importcheck: PE import audit against the flavour's OS floor list (04 §2.4). Build-time tool.
# Applied to every shipping executable by sd_add_app (post-build step + CTest "importcheck.*").

add_executable(sd-importcheck sd-importcheck.c)
set_target_properties(sd-importcheck PROPERTIES FOLDER "tools")
