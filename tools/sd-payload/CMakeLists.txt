# sd-payload: attaches the setup payload to a copy of the setup stub (04 §6.1). Build-time tool, never
# shipped. It shares the SHA-256 code of the engine (self-contained file, windows.h only).

add_executable(sd-payload sd-payload.c "${CMAKE_SOURCE_DIR}/apps/shelldrive-setup/setup_sha256.c")
set_target_properties(sd-payload PROPERTIES FOLDER "tools")
