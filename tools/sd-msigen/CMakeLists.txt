# sd-msigen: MSI generator (docs/design/04 §8). Build-time tool, never shipped; built by packaging/msi only.
add_executable(sd-msigen sd-msigen.c)
set_target_properties(sd-msigen PROPERTIES FOLDER "tools")
