
# Compilation configuration

## Environment variables

2 environment variables needed :

  * `PINTOOL_DIR` : pintool installation, so folder `$(PINTOOL_DIR)/source/include/pin` exists
  * `WIN10SDK_INCLUDE` : SDK installation dir, so `$(WIN10SDK_INCLUDE)/um/windows.h`  exists (should me something like `C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0`)

Add them through `sysdm.cpl` > Advanced > Envrionment Variables