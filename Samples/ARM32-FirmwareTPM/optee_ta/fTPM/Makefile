BINARY=bc50d971-d4c9-42c4-82cb-343fb7f37896

O := ../out/TAs/fTPM
WOLF_ROOT := ../../wolfssl/

CFLAGS += -fshort-wchar
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

clean: clean_stripped_file clean_wolf
.PHONY: clean_stripped_file
clean_stripped_file:
	rm -f $(BINARY).stripped.elf
.PHONY: clean_wolf
clean_wolf:
	rm -rf $(O)/$(WOLF_ROOT)
