# sd-msiembed: embeds language transforms into an MSI (docs/design/04 §8.6). Build-time tool, never shipped.
add_executable(sd-msiembed sd-msiembed.c)
target_link_libraries(sd-msiembed PRIVATE msi.lib) # the import library, not the msi target name
set_target_properties(sd-msiembed PROPERTIES FOLDER "tools")
